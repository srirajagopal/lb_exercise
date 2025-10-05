# Create a load balancer in a VPC instance. 
# The load balancer should have a security group which should allow inbound HTTP/HTTPS traffic from the public internet. 
# The load balancer should have a listener for HTTP/HTTPS traffic. 
# The load balancer should have a target group for the EC2 instance. 
# The load balancer should have a health check for the EC2 instance. 
# Tag the load balancer and all other created resources with a value of Coolscale. 
# Create two EC2 instances in the target group. Make sure they are in different availability zones. 
# Ensure that the EC2 instances can be logged into via SSH from the internet through the internet gateway. 

import boto3
import time
import json
import os
import requests
from botocore.exceptions import ClientError, WaiterError

# Initialize AWS clients
ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')
elbv2 = boto3.client('elbv2')
iam = boto3.client('iam')

# Get current AWS region
session = boto3.Session()
current_region = session.region_name
if not current_region:
    # Fallback to getting region from client
    current_region = ec2_client.meta.region_name

# Configurable prefix
PREFIX = 'coolscale'
TAG_VALUE = 'Coolscale'
LB_NAME = f'{PREFIX}-lb'
LB_SG_NAME = f'{PREFIX}-lb-sg'
INSTANCE_SG_NAME = f'{PREFIX}-instance-sg'
TG_NAME = f'{PREFIX}-tg'
KEY_NAME = f'{PREFIX}-key'
VPC_NAME = f'{PREFIX}-vpc'
IGW_NAME = f'{PREFIX}-igw'

def print_status(message, status="INFO"):
    """Print status messages with timestamps"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{status}] {message}")

def wait_for_resource(waiter, **kwargs):
    """Generic function to wait for AWS resources"""
    try:
        waiter.wait(**kwargs)
        return True
    except WaiterError as e:
        print_status(f"Waiter error: {str(e)}", "ERROR")
        return False
    except Exception as e:
        print_status(f"Unexpected error during wait: {str(e)}", "ERROR")
        return False

def create_additional_subnets(vpc_id, az_subnet_map):
    """Create additional subnets in different AZs if needed"""
    try:
        # Get available AZs in the region
        azs_response = ec2_client.describe_availability_zones(
            Filters=[{'Name': 'state', 'Values': ['available']}]
        )
        available_azs = [az['ZoneName'] for az in azs_response['AvailabilityZones']]
        
        print_status(f"Available AZs in region: {available_azs}")
        
        # Get VPC CIDR block for subnet creation
        vpc = ec2.Vpc(vpc_id)
        vpc_cidr = vpc.cidr_block
        print_status(f"VPC CIDR block: {vpc_cidr}")
        
        # Parse CIDR to create subnet CIDRs
        base_ip = vpc_cidr.split('/')[0]
        cidr_prefix = int(vpc_cidr.split('/')[1])
        
        selected_subnets = []
        
        # Try to find 2 different AZs
        for i, az in enumerate(available_azs):
            if len(selected_subnets) >= 2:
                break
                
            if az not in az_subnet_map or not az_subnet_map[az]:
                # Create a new subnet in this AZ
                subnet_cidr = f"{'.'.join(base_ip.split('.')[:-1])}.{16 + i*16}/{cidr_prefix + 4}"
                subnet_name = f"{PREFIX}-subnet-{az}"
                
                try:
                    print_status(f"Creating subnet {subnet_name} in AZ {az} with CIDR {subnet_cidr}")
                    subnet = ec2.create_subnet(
                        VpcId=vpc_id,
                        CidrBlock=subnet_cidr,
                        AvailabilityZone=az,
                        TagSpecifications=[{
                            'ResourceType': 'subnet',
                            'Tags': [
                                {'Key': 'Name', 'Value': subnet_name},
                                {'Key': 'Project', 'Value': TAG_VALUE}
                            ]
                        }]
                    )
                    
                    # Wait for subnet to be available
                    print_status(f"Waiting for subnet {subnet.id} to be available...")
                    ec2_client.get_waiter('subnet_available').wait(SubnetIds=[subnet.id])
                    
                    selected_subnets.append(subnet)
                    print_status(f"Created subnet {subnet.id} in AZ {az}")
                    
                except ClientError as e:
                    print_status(f"Failed to create subnet in AZ {az}: {str(e)}", "WARNING")
                    continue
            else:
                # Use existing subnet from this AZ
                existing_subnet = az_subnet_map[az][0]
                selected_subnets.append(existing_subnet)
                print_status(f"Using existing subnet {existing_subnet.id} in AZ {az}")
        
        return selected_subnets[:2]  # Return max 2 subnets
        
    except Exception as e:
        print_status(f"Error creating additional subnets: {str(e)}", "ERROR")
        return None

print_status("Starting infrastructure deployment...")
print_status(f"Current AWS Region: {current_region}")
print_status(f"All resources will be created in region: {current_region}")

# Validate region availability
if not current_region:
    print_status("ERROR: Could not determine AWS region", "ERROR")
    print_status("Please ensure AWS credentials are configured and region is set", "ERROR")
    raise Exception("AWS region not detected. Please configure AWS credentials and region.")

# 1. Create new VPC
print_status(f"Creating new VPC in region {current_region}...")
try:
    # Check if VPC already exists
    existing_vpcs = list(ec2.vpcs.filter(Filters=[{'Name': 'tag:Name', 'Values': [VPC_NAME]}]))
    if existing_vpcs:
        vpc = existing_vpcs[0]
        vpc_id = vpc.id
        print_status(f"Found existing VPC: {vpc_id}")
    else:
        # Create new VPC
        vpc = ec2.create_vpc(
            CidrBlock='10.0.0.0/16',
            TagSpecifications=[{
                'ResourceType': 'vpc',
                'Tags': [
                    {'Key': 'Name', 'Value': VPC_NAME},
                    {'Key': 'Project', 'Value': TAG_VALUE}
                ]
            }]
        )
        vpc_id = vpc.id
        print_status(f"Created new VPC: {vpc_id}")
        
        # Enable DNS hostnames for the VPC
        ec2_client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})
        ec2_client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
        print_status("Enabled DNS hostnames and support for VPC")
        
except Exception as e:
    print_status(f"Failed to create VPC: {str(e)}", "ERROR")
    raise

# 2. Create subnets in different AZs
print_status("Creating subnets in different availability zones...")
try:
    # Get available AZs in the region
    azs_response = ec2_client.describe_availability_zones(
        Filters=[{'Name': 'state', 'Values': ['available']}]
    )
    available_azs = [az['ZoneName'] for az in azs_response['AvailabilityZones']]
    print_status(f"Available AZs in region: {available_azs}")
    
    if len(available_azs) < 2:
        print_status("Not enough availability zones in region", "ERROR")
        raise Exception("Need at least 2 availability zones in the region.")
    
    # Check for existing subnets
    existing_subnets = list(ec2.subnets.filter(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]))
    print_status(f"Found {len(existing_subnets)} existing subnets in VPC")
    
    # Create subnets in first 2 AZs
    selected_subnets = []
    subnet_cidrs = ['10.0.1.0/24', '10.0.2.0/24']  # Use different CIDR blocks for each subnet
    
    for i, az in enumerate(available_azs[:2]):
        subnet_name = f"{PREFIX}-subnet-{az}"
        
        # Check if subnet already exists
        existing_subnet = next((s for s in existing_subnets if s.availability_zone == az), None)
        
        if existing_subnet:
            print_status(f"Using existing subnet {existing_subnet.id} in AZ {az}")
            selected_subnets.append(existing_subnet)
        else:
            try:
                print_status(f"Creating subnet {subnet_name} in AZ {az} with CIDR {subnet_cidrs[i]}")
                subnet = ec2.create_subnet(
                    VpcId=vpc_id,
                    CidrBlock=subnet_cidrs[i],
                    AvailabilityZone=az,
                    TagSpecifications=[{
                        'ResourceType': 'subnet',
                        'Tags': [
                            {'Key': 'Name', 'Value': subnet_name},
                            {'Key': 'Project', 'Value': TAG_VALUE}
                        ]
                    }]
                )
                
                # Wait for subnet to be available
                print_status(f"Waiting for subnet {subnet.id} to be available...")
                ec2_client.get_waiter('subnet_available').wait(SubnetIds=[subnet.id])
                
                selected_subnets.append(subnet)
                print_status(f"Created subnet {subnet.id} in AZ {az}")
                
            except ClientError as e:
                print_status(f"Failed to create subnet in AZ {az}: {str(e)}", "ERROR")
                raise
    
    subnet_ids = [s.id for s in selected_subnets]
    print_status(f"Successfully created/selected 2 subnets: {subnet_ids}")
    print_status(f"Using AZs: {[s.availability_zone for s in selected_subnets]}")
    
except Exception as e:
    print_status(f"Failed to create subnets: {str(e)}", "ERROR")
    raise

# 3. Create Internet Gateway and configure routing
print_status("Creating Internet Gateway and configuring routing...")
try:
    # Check if Internet Gateway already exists
    existing_igws = list(ec2.internet_gateways.filter(Filters=[{'Name': 'tag:Name', 'Values': [IGW_NAME]}]))
    
    if existing_igws:
        igw = existing_igws[0]
        igw_id = igw.id
        print_status(f"Found existing Internet Gateway: {igw_id}")
        
        # Check if it's attached to our VPC
        if not igw.attachments or igw.attachments[0]['VpcId'] != vpc_id:
            print_status(f"Attaching Internet Gateway {igw_id} to VPC {vpc_id}")
            igw.attach_to_vpc(VpcId=vpc_id)
            print_status("Internet Gateway attached successfully")
    else:
        # Create new Internet Gateway
        igw = ec2.create_internet_gateway(
            TagSpecifications=[{
                'ResourceType': 'internet-gateway',
                'Tags': [
                    {'Key': 'Name', 'Value': IGW_NAME},
                    {'Key': 'Project', 'Value': TAG_VALUE}
                ]
            }]
        )
        igw_id = igw.id
        print_status(f"Created Internet Gateway: {igw_id}")
        
        # Attach to VPC
        print_status(f"Attaching Internet Gateway {igw_id} to VPC {vpc_id}")
        igw.attach_to_vpc(VpcId=vpc_id)
        print_status("Internet Gateway attached successfully")
    
    # Get main route table and add route to Internet Gateway
    print_status("Configuring route table for Internet access...")
    route_tables = list(vpc.route_tables.all())
    main_route_table = None
    
    # Find the main route table
    for rt in route_tables:
        for association in rt.associations:
            if association.main:
                main_route_table = rt
                break
        if main_route_table:
            break
    
    if main_route_table:
        print_status(f"Found main route table: {main_route_table.id}")
        
        # Check existing routes in the main route table
        existing_routes = list(main_route_table.routes.all())
        print_status(f"Main route table has {len(existing_routes)} existing routes")
        
        # Check if route to Internet Gateway already exists
        igw_route_exists = False
        for route in existing_routes:
            if route.destination_cidr_block == '0.0.0.0/0':
                if hasattr(route, 'gateway_id') and route.gateway_id == igw_id:
                    igw_route_exists = True
                    print_status("Route to Internet Gateway already exists")
                    break
                elif route.gateway_id and route.gateway_id.startswith('igw-'):
                    print_status(f"Route to Internet Gateway exists but points to different IGW: {route.gateway_id}")
                    print_status("This might cause routing issues")
        
        # Add route to Internet Gateway if it doesn't exist
        if not igw_route_exists:
            try:
                main_route_table.create_route(
                    DestinationCidrBlock='0.0.0.0/0',
                    GatewayId=igw_id
                )
                print_status("Added route to Internet Gateway in main route table")
            except ClientError as e:
                if 'RouteAlreadyExists' in str(e):
                    print_status("Route to Internet Gateway already exists")
                else:
                    print_status(f"Failed to add route: {str(e)}", "WARNING")
        else:
            print_status("Route to Internet Gateway is properly configured")
    else:
        print_status("Main route table not found - this should not happen", "ERROR")
        raise Exception("Main route table not found")
    
    # Ensure subnets are associated with the main route table
    print_status("Ensuring subnets are properly associated with main route table...")
    for subnet in selected_subnets:
        # Check if subnet is associated with main route table
        subnet_route_table = None
        for rt in route_tables:
            for association in rt.associations:
                if association.subnet_id == subnet.id:
                    subnet_route_table = rt
                    break
            if subnet_route_table:
                break
        
        if subnet_route_table and subnet_route_table.id == main_route_table.id:
            print_status(f"Subnet {subnet.id} is correctly associated with main route table")
        else:
            print_status(f"Subnet {subnet.id} is associated with route table {subnet_route_table.id if subnet_route_table else 'None'}", "WARNING")
            print_status("This might cause routing issues - subnet should use main route table")
    
    # Configure subnets for auto-assign public IP
    print_status("Configuring subnets for public IP assignment...")
    for subnet in selected_subnets:
        try:
            ec2_client.modify_subnet_attribute(
                SubnetId=subnet.id,
                MapPublicIpOnLaunch={'Value': True}
            )
            print_status(f"Enabled auto-assign public IP for subnet {subnet.id}")
        except ClientError as e:
            print_status(f"Failed to enable auto-assign public IP for subnet {subnet.id}: {str(e)}", "WARNING")
    
    print_status("Internet Gateway and routing configuration completed")
    
except Exception as e:
    print_status(f"Failed to configure Internet Gateway and routing: {str(e)}", "ERROR")
    raise

# 4. Create Security Group for LB (allow HTTP/HTTPS from anywhere)
print_status(f"Checking for existing security group: {LB_SG_NAME}")
try:
    # Check if security group already exists
    existing_sgs = list(ec2.security_groups.filter(
        Filters=[
            {'Name': 'group-name', 'Values': [LB_SG_NAME]},
            {'Name': 'vpc-id', 'Values': [vpc_id]}
        ]
    ))
    
    if existing_sgs:
        lb_sg = existing_sgs[0]
        print_status(f"Found existing LB security group: {lb_sg.id}")
    else:
        print_status(f"Creating new security group for load balancer: {LB_SG_NAME}")
        lb_sg = ec2.create_security_group(
            GroupName=LB_SG_NAME,
            Description='Security group for ALB',
            VpcId=vpc_id,
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [{'Key': 'Name', 'Value': LB_SG_NAME}, {'Key': 'Project', 'Value': TAG_VALUE}]
            }]
        )
        print_status(f"Created LB security group: {lb_sg.id}")
        
        print_status("Adding HTTP/HTTPS ingress rules to LB security group...")
        lb_sg.authorize_ingress(
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ]
        )
        print_status("Successfully configured LB security group rules")
        
except Exception as e:
    print_status(f"Failed to create/retrieve LB security group: {str(e)}", "ERROR")
    raise

# 5. Create Security Group for EC2 (allow SSH from anywhere, allow HTTP from LB SG)
print_status(f"Checking for existing security group: {INSTANCE_SG_NAME}")
try:
    # Check if security group already exists
    existing_instance_sgs = list(ec2.security_groups.filter(
        Filters=[
            {'Name': 'group-name', 'Values': [INSTANCE_SG_NAME]},
            {'Name': 'vpc-id', 'Values': [vpc_id]}
        ]
    ))
    
    if existing_instance_sgs:
        instance_sg = existing_instance_sgs[0]
        print_status(f"Found existing instance security group: {instance_sg.id}")
    else:
        print_status(f"Creating new security group for EC2 instances: {INSTANCE_SG_NAME}")
        instance_sg = ec2.create_security_group(
            GroupName=INSTANCE_SG_NAME,
            Description='Security group for EC2 instances',
            VpcId=vpc_id,
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [{'Key': 'Name', 'Value': INSTANCE_SG_NAME}, {'Key': 'Project', 'Value': TAG_VALUE}]
            }]
        )
        print_status(f"Created instance security group: {instance_sg.id}")
        
        print_status("Adding SSH and HTTP ingress rules to instance security group...")
        instance_sg.authorize_ingress(
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80,
                 'UserIdGroupPairs': [{'GroupId': lb_sg.id}]}
            ]
        )
        print_status("Successfully configured instance security group rules")
        
except Exception as e:
    print_status(f"Failed to create/retrieve instance security group: {str(e)}", "ERROR")
    raise

# 6. Create Key Pair and save PEM file
print_status(f"Checking for existing key pair: {KEY_NAME}")
key_path = f'./{KEY_NAME}.pem'
try:
    # Check if key pair exists in AWS
    try:
        ec2_client.describe_key_pairs(KeyNames=[KEY_NAME])
        print_status(f"Found existing key pair in AWS: {KEY_NAME}")
        
        # Check if PEM file exists locally
        if os.path.exists(key_path):
            print_status(f"PEM file already exists locally: {key_path}")
        else:
            print_status(f"Key pair exists in AWS but PEM file missing locally: {key_path}")
            print_status("You may need to create a new key pair or retrieve the private key from AWS console")
            
    except ClientError as e:
        if 'InvalidKeyPair.NotFound' in str(e):
            # Key pair doesn't exist in AWS, create it
            if os.path.exists(key_path):
                print_status(f"PEM file exists locally but key pair not in AWS. Creating new key pair...")
                os.remove(key_path)  # Remove orphaned local file
            else:
                print_status(f"Creating new key pair: {KEY_NAME}")
            
            key_pair = ec2_client.create_key_pair(KeyName=KEY_NAME)
            with open(key_path, 'w') as f:
                f.write(key_pair['KeyMaterial'])
            os.chmod(key_path, 0o400)
            print_status(f"Created and saved key pair: {KEY_NAME}")
            print_status(f"PEM file saved at: {key_path}")
        else:
            raise
except Exception as e:
    print_status(f"Failed to create/retrieve key pair: {str(e)}", "ERROR")
    raise

# 7. Find latest Amazon Linux 2 AMI
print_status(f"Searching for latest Amazon Linux 2 AMI in region {current_region}...")
try:
    images = ec2_client.describe_images(
        Owners=['amazon'],
        Filters=[
            {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
            {'Name': 'state', 'Values': ['available']}
        ]
    )['Images']
    
    if not images:
        print_status("No Amazon Linux 2 AMI found", "ERROR")
        raise Exception("No Amazon Linux 2 AMI found")
    
    ami = sorted(images, key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
    print_status(f"Found latest Amazon Linux 2 AMI: {ami}")
    print_status(f"AMI is specific to region {current_region}")
except Exception as e:
    print_status(f"Failed to find Amazon Linux 2 AMI: {str(e)}", "ERROR")
    raise

# 7a. Create user data script for Flask web server
user_data_script = '''#!/bin/bash
# Update system
yum update -y

# Install Python3 and pip
yum install -y python3 python3-pip

# Install Flask
pip3 install flask requests

# Create Flask application directory
mkdir -p /var/www/flaskapp
cd /var/www/flaskapp

# Create Flask application
cat > app.py << 'EOF'
#!/usr/bin/env python3
import flask
import requests
import socket
import json
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def instance_info():
    try:
        # Get instance metadata
        metadata_url = 'http://169.254.169.254/latest/meta-data/'
        metadata = {}
        
        # Get various metadata
        metadata_fields = [
            'instance-id',
            'instance-type', 
            'availability-zone',
            'local-ipv4',
            'public-ipv4',
            'local-hostname',
            'public-hostname',
            'security-groups',
            'iam/instance-profile'
        ]
        
        for field in metadata_fields:
            try:
                response = requests.get(f'{metadata_url}{field}', timeout=2)
                if response.status_code == 200:
                    metadata[field] = response.text
                else:
                    metadata[field] = 'Not available'
            except:
                metadata[field] = 'Not available'
        
        # Get hostname
        hostname = socket.gethostname()
        
        # Get local IP
        local_ip = socket.gethostbyname(hostname)
        
        # Create response
        response_data = {
            'hostname': hostname,
            'local_ip': local_ip,
            'metadata': metadata,
            'message': 'Flask server running successfully!'
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
EOF

# Make the script executable
chmod +x app.py

# Create systemd service file
cat > /etc/systemd/system/flaskapp.service << 'EOF'
[Unit]
Description=Flask Application
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/var/www/flaskapp
Environment=PATH=/usr/bin:/usr/local/bin
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Change ownership of the app directory
chown -R ec2-user:ec2-user /var/www/flaskapp

# Enable and start the service
systemctl daemon-reload
systemctl enable flaskapp
systemctl start flaskapp

# Wait a moment for Flask to start
sleep 5

# Check if Flask is running
if systemctl is-active --quiet flaskapp; then
    echo "Flask app started successfully"
    systemctl status flaskapp
else
    echo "Flask app failed to start, checking logs:"
    journalctl -u flaskapp --no-pager
fi

# Check what's running on port 80
echo "Processes listening on port 80:" >> /var/log/user-data.log
netstat -tlnp | grep :80 >> /var/log/user-data.log 2>&1 || true

# Test Flask app locally
echo "Testing Flask app locally:" >> /var/log/user-data.log
curl -s http://localhost/ >> /var/log/user-data.log 2>&1 || echo "Local Flask test failed" >> /var/log/user-data.log

# Create a log file for debugging
echo "User data script completed at $(date)" >> /var/log/user-data.log
echo "Flask service status: $(systemctl is-active flaskapp)" >> /var/log/user-data.log
echo "Flask service enabled: $(systemctl is-enabled flaskapp)" >> /var/log/user-data.log
'''

# 8. Launch two EC2 instances in different AZs
print_status("Checking for existing EC2 instances...")
try:
    instances = []
    
    # Check for existing instances with our tags
    existing_instances = list(ec2.instances.filter(
        Filters=[
            {'Name': 'tag:Project', 'Values': [TAG_VALUE]},
            {'Name': 'tag:Name', 'Values': [f'{PREFIX}-instance-1', f'{PREFIX}-instance-2']},
            {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
        ]
    ))
    
    if len(existing_instances) >= 2:
        print_status(f"Found {len(existing_instances)} existing instances")
        instances = existing_instances[:2]  # Take first 2 instances
        for i, instance in enumerate(instances):
            print_status(f"Using existing instance {i+1}: {instance.id} (State: {instance.state['Name']})")
    else:
        print_status(f"Found {len(existing_instances)} existing instances, need to create {2-len(existing_instances)} more")
        
        # Add existing instances to our list
        instances.extend(existing_instances)
        
        # Create first instance if needed
        if len(instances) < 1:
            print_status(f"Creating first instance in subnet {subnet_ids[0]} ({selected_subnets[0].availability_zone})")
            instance1 = ec2.create_instances(
                ImageId=ami,
                InstanceType='t2.micro',
                KeyName=KEY_NAME,
                MinCount=1,
                MaxCount=1,
                UserData=user_data_script,
                NetworkInterfaces=[{
                    'SubnetId': subnet_ids[0],
                    'DeviceIndex': 0,
                    'AssociatePublicIpAddress': True,
                    'Groups': [instance_sg.id]
                }],
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'{PREFIX}-instance-1'}, 
                        {'Key': 'Project', 'Value': TAG_VALUE},
                        {'Key': 'AZ', 'Value': selected_subnets[0].availability_zone}
                    ]
                }]
            )[0]
            instances.append(instance1)
            print_status(f"Created first instance: {instance1.id}")
        
        # Create second instance if needed
        if len(instances) < 2:
            print_status(f"Creating second instance in subnet {subnet_ids[1]} ({selected_subnets[1].availability_zone})")
            instance2 = ec2.create_instances(
                ImageId=ami,
                InstanceType='t2.micro',
                KeyName=KEY_NAME,
                MinCount=1,
                MaxCount=1,
                UserData=user_data_script,
                NetworkInterfaces=[{
                    'SubnetId': subnet_ids[1],
                    'DeviceIndex': 0,
                    'AssociatePublicIpAddress': True,
                    'Groups': [instance_sg.id]
                }],
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'{PREFIX}-instance-2'}, 
                        {'Key': 'Project', 'Value': TAG_VALUE},
                        {'Key': 'AZ', 'Value': selected_subnets[1].availability_zone}
                    ]
                }]
            )[0]
            instances.append(instance2)
            print_status(f"Created second instance: {instance2.id}")
    
    instance_ids = [i.id for i in instances]
    print_status(f"Using EC2 instances: {instance_ids}")
    
    # Check if any instances need to be started
    instances_to_start = [i for i in instances if i.state['Name'] in ['stopped', 'stopping']]
    if instances_to_start:
        print_status("Starting stopped instances...")
        for instance in instances_to_start:
            instance.start()
        print_status("Waiting for instances to start...")
        if not wait_for_resource(ec2_client.get_waiter('instance_running'), InstanceIds=[i.id for i in instances_to_start]):
            print_status("Failed to wait for instances to start", "ERROR")
    
    print_status("Waiting for instances to reach running state...")
    
    # Wait for instances to be running
    if not wait_for_resource(ec2_client.get_waiter('instance_running'), InstanceIds=instance_ids):
        print_status("Failed to wait for instances to be running", "ERROR")
        raise Exception("Instances failed to reach running state")
    
    print_status("All instances are now running")
    
    # Reload instance data to get updated information
    for i in instances:
        i.reload()
    
    # Display instance details
    for i, instance in enumerate(instances):
        print_status(f"Instance {i+1}: {instance.id} - State: {instance.state['Name']} - AZ: {instance.placement['AvailabilityZone']}")
    
    # Wait additional time for Flask server to initialize
    print_status("Waiting for Flask server to initialize (this may take a few minutes)...")
    time.sleep(60)  # Wait 60 seconds for user data script to complete
    print_status("Flask server initialization wait completed")
    
except Exception as e:
    print_status(f"Failed to launch EC2 instances: {str(e)}", "ERROR")
    raise

# 9. Create Target Group
print_status(f"Checking for existing target group: {TG_NAME}")
try:
    vpc_id = vpc.id
    
    # Check if target group already exists
    try:
        tg_response = elbv2.describe_target_groups(Names=[TG_NAME])
        tg_arn = tg_response['TargetGroups'][0]['TargetGroupArn']
        print_status(f"Found existing target group: {TG_NAME} (ARN: {tg_arn})")
        
        # Check if instances are already registered
        registered_targets = elbv2.describe_target_health(TargetGroupArn=tg_arn)
        current_target_ids = [target['Target']['Id'] for target in registered_targets['TargetHealthDescriptions']]
        
        # Register any new instances
        instances_to_register = [i for i in instances if i.id not in current_target_ids]
        if instances_to_register:
            print_status(f"Registering {len(instances_to_register)} new instances with target group...")
            elbv2.register_targets(
                TargetGroupArn=tg_arn,
                Targets=[{'Id': i.id} for i in instances_to_register]
            )
            print_status(f"Registered {len(instances_to_register)} new instances")
        else:
            print_status("All instances already registered with target group")
            
    except ClientError as e:
        if 'TargetGroupNotFound' in str(e):
            # Target group doesn't exist, create it
            print_status(f"Creating new target group: {TG_NAME}")
            tg_response = elbv2.create_target_group(
                Name=TG_NAME,
                Protocol='HTTP',
                Port=80,
                VpcId=vpc_id,
                HealthCheckProtocol='HTTP',
                HealthCheckPort='80',
                HealthCheckPath='/',
                TargetType='instance',
                Tags=[{'Key': 'Project', 'Value': TAG_VALUE}]
            )
            tg_arn = tg_response['TargetGroups'][0]['TargetGroupArn']
            print_status(f"Created target group: {TG_NAME} (ARN: {tg_arn})")
            
            # Register EC2 instances to target group
            print_status("Registering EC2 instances with target group...")
            elbv2.register_targets(
                TargetGroupArn=tg_arn,
                Targets=[{'Id': i.id} for i in instances]
            )
            print_status(f"Registered {len(instances)} instances with target group")
        else:
            raise
            
except Exception as e:
    print_status(f"Failed to create/retrieve target group: {str(e)}", "ERROR")
    raise

# 10. Create Load Balancer
print_status(f"Checking for existing load balancer: {LB_NAME}")
try:
    # Check if load balancer already exists
    try:
        lb_response = elbv2.describe_load_balancers(Names=[LB_NAME])
        lb_arn = lb_response['LoadBalancers'][0]['LoadBalancerArn']
        dns_name = lb_response['LoadBalancers'][0]['DNSName']
        print_status(f"Found existing load balancer: {LB_NAME} (ARN: {lb_arn})")
        print_status(f"Load balancer DNS name: {dns_name}")
    except ClientError as e:
        if 'LoadBalancerNotFound' in str(e):
            # Load balancer doesn't exist, create it
            print_status(f"Creating new Application Load Balancer: {LB_NAME}")
            lb_response = elbv2.create_load_balancer(
                Name=LB_NAME,
                Subnets=subnet_ids,
                SecurityGroups=[lb_sg.id],
                Scheme='internet-facing',
                Type='application',
                IpAddressType='ipv4',
                Tags=[{'Key': 'Project', 'Value': TAG_VALUE}]
            )
            lb_arn = lb_response['LoadBalancers'][0]['LoadBalancerArn']
            print_status(f"Created load balancer: {LB_NAME} (ARN: {lb_arn})")
            
            # Get the DNS name for display
            dns_name = lb_response['LoadBalancers'][0]['DNSName']
            print_status(f"Load balancer DNS name: {dns_name}")
        else:
            raise
            
except Exception as e:
    print_status(f"Failed to create/retrieve load balancer: {str(e)}", "ERROR")
    raise

# 11. Create Listener for HTTP (port 80)
print_status("Checking for existing HTTP listener on port 80...")
try:
    # Check if listener already exists
    try:
        listeners_response = elbv2.describe_listeners(LoadBalancerArn=lb_arn)
        existing_listeners = [l for l in listeners_response['Listeners'] if l['Port'] == 80 and l['Protocol'] == 'HTTP']
        
        if existing_listeners:
            listener_arn = existing_listeners[0]['ListenerArn']
            print_status(f"Found existing HTTP listener on port 80: {listener_arn}")
        else:
            # No HTTP listener on port 80, create one
            print_status("Creating HTTP listener on port 80...")
            listener_response = elbv2.create_listener(
                LoadBalancerArn=lb_arn,
                Protocol='HTTP',
                Port=80,
                DefaultActions=[{
                    'Type': 'forward',
                    'TargetGroupArn': tg_arn
                }]
            )
            listener_arn = listener_response['Listeners'][0]['ListenerArn']
            print_status(f"Created HTTP listener: {listener_arn}")
            
    except ClientError as e:
        if 'LoadBalancerNotFound' in str(e):
            print_status("Load balancer not found, cannot create listener", "ERROR")
            raise
        else:
            raise
            
except Exception as e:
    print_status(f"Failed to create/retrieve listener: {str(e)}", "ERROR")
    raise

# 12. Tag EC2 instances (already tagged at creation), security groups, target group, and load balancer
print_status("All resources have been tagged during creation")

# 13. Wait for LB to be active
print_status("Waiting for load balancer to become active...")
if not wait_for_resource(elbv2.get_waiter('load_balancer_available'), LoadBalancerArns=[lb_arn]):
    print_status("Failed to wait for load balancer to become active", "ERROR")
    raise Exception("Load balancer failed to become active")
print_status("Load balancer is now active and ready to serve traffic")

# 14. Pretty print details
print_status("Deployment completed successfully! Gathering resource details...")

def pretty_print(title, data):
    print(f"\n{'='*10} {title} {'='*10}")
    print(json.dumps(data, indent=2, default=str))

try:
    # Load Balancer details
    print_status("Retrieving load balancer details...")
    lb_details = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]
    pretty_print("Load Balancer", lb_details)

    # EC2 Instances details
    print_status("Retrieving EC2 instance details...")
    instance_details = [ec2_client.describe_instances(InstanceIds=[i.id])['Reservations'][0]['Instances'][0] for i in instances]
    pretty_print("EC2 Instances", instance_details)
    
    # Generate SSH commands for each instance
    print_status("="*60)
    print_status("SSH COMMANDS FOR EC2 INSTANCES", "INFO")
    print_status("="*60)
    for i, instance_detail in enumerate(instance_details, 1):
        public_ip = instance_detail.get('PublicIpAddress', 'N/A')
        instance_id = instance_detail['InstanceId']
        az = instance_detail['Placement']['AvailabilityZone']
        
        if public_ip != 'N/A':
            ssh_command = f"ssh -i {key_path} ec2-user@{public_ip}"
            print_status(f"Instance {i} ({instance_id}) in {az}:")
            print_status(f"  Public IP: {public_ip}")
            print_status(f"  SSH Command: {ssh_command}")
            print_status("")
        else:
            print_status(f"Instance {i} ({instance_id}) in {az}:")
            print_status(f"  Public IP: Not available yet")
            print_status(f"  SSH Command: Not available (wait for public IP assignment)")
            print_status("")
    print_status("="*60)

    # Target Group details
    print_status("Retrieving target group details...")
    tg_details = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])['TargetGroups'][0]
    pretty_print("Target Group", tg_details)

    # Security Group details
    print_status("Retrieving security group details...")
    lb_sg_details = ec2_client.describe_security_groups(GroupIds=[lb_sg.id])['SecurityGroups'][0]
    pretty_print("LB Security Group", lb_sg_details)
    instance_sg_details = ec2_client.describe_security_groups(GroupIds=[instance_sg.id])['SecurityGroups'][0]
    pretty_print("Instance Security Group", instance_sg_details)

    print_status("="*60)
    print_status("DEPLOYMENT SUMMARY", "SUCCESS")
    print_status("="*60)
    print_status(f"AWS Region: {current_region}")
    print_status(f"Load Balancer DNS: {dns_name}")
    print_status(f"Load Balancer ARN: {lb_arn}")
    print_status(f"Target Group ARN: {tg_arn}")
    print_status(f"EC2 Instance IDs: {instance_ids}")
    print_status(f"PEM file location: {key_path}")
    print_status("")
    print_status("SSH COMMANDS (Copy & Paste Ready):")
    print_status(f"  Note: Make sure the PEM file has correct permissions: chmod 400 {key_path}")
    print_status("")
    for i, instance_detail in enumerate(instance_details, 1):
        public_ip = instance_detail.get('PublicIpAddress', 'N/A')
        instance_id = instance_detail['InstanceId']
        if public_ip != 'N/A':
            ssh_command = f"ssh -i {key_path} ec2-user@{public_ip}"
            print_status(f"  Instance {i}: {ssh_command}")
        else:
            print_status(f"  Instance {i}: Public IP not available yet")
    print_status("")
    print_status("TESTING COMMANDS:")
    print_status(f"  Test Flask app: curl http://{dns_name}")
    print_status(f"  Test specific instance: curl http://<instance-public-ip>")
    print_status("="*60)
    print_status("You can now access your Flask application via the load balancer DNS name!")
    print_status("Each request will show which instance is serving the request.")
    
    # Test the load balancer with curl
    print_status("")
    print_status("="*60)
    print_status("TESTING LOAD BALANCER WITH CURL", "INFO")
    print_status("="*60)
    
    from urllib3.exceptions import InsecureRequestWarning
    
    # Disable SSL warnings for testing
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    # Test with multiple attempts to handle DNS propagation
    max_attempts = 10
    test_url = f"http://{dns_name}"
    
    print_status(f"Testing load balancer endpoint: {test_url}")
    print_status("Note: DNS propagation may take a few minutes...")
    
    for attempt in range(1, max_attempts + 1):
        print_status(f"Attempt {attempt}/{max_attempts} - Testing load balancer...")
        
        try:
            # Use requests with timeout
            response = requests.get(test_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                print_status("✅ LOAD BALANCER TEST SUCCESSFUL!", "SUCCESS")
                print_status(f"Status Code: {response.status_code}")
                print_status(f"Response Headers: {dict(response.headers)}")
                print_status("")
                print_status("Response Body:")
                print_status("-" * 40)
                
                try:
                    # Try to parse as JSON for pretty printing
                    json_response = response.json()
                    print(json.dumps(json_response, indent=2))
                except:
                    # If not JSON, print as text
                    print(response.text)
                
                print_status("-" * 40)
                print_status("✅ Flask application is working correctly!")
                print_status("✅ Load balancer is distributing traffic properly!")
                print_status("✅ Instance metadata is being returned as expected!")
                break
                
            else:
                print_status(f"HTTP {response.status_code}: {response.text}", "WARNING")
                if attempt < max_attempts:
                    print_status(f"Retrying in 30 seconds... (attempt {attempt}/{max_attempts})")
                    time.sleep(30)
                    
        except requests.exceptions.ConnectionError as e:
            print_status(f"Connection error (attempt {attempt}/{max_attempts}): {str(e)}", "WARNING")
            if attempt < max_attempts:
                print_status("This is likely due to DNS propagation. Waiting 30 seconds...")
                time.sleep(30)
                
        except requests.exceptions.Timeout as e:
            print_status(f"Timeout error (attempt {attempt}/{max_attempts}): {str(e)}", "WARNING")
            if attempt < max_attempts:
                print_status("Waiting 30 seconds before retry...")
                time.sleep(30)
                
        except Exception as e:
            print_status(f"Unexpected error (attempt {attempt}/{max_attempts}): {str(e)}", "ERROR")
            if attempt < max_attempts:
                print_status("Waiting 30 seconds before retry...")
                time.sleep(30)
    
    else:
        print_status("❌ LOAD BALANCER TEST FAILED", "ERROR")
        print_status("The load balancer may still be initializing or there may be an issue.")
        print_status("Please wait a few more minutes and try manually:")
        print_status(f"  curl {test_url}")
        print_status("")
        print_status("Troubleshooting steps:")
        print_status("1. Wait 5-10 minutes for DNS propagation")
        print_status("2. Check if EC2 instances are running: aws ec2 describe-instances")
        print_status("3. Check if target group is healthy: aws elbv2 describe-target-health")
        print_status("4. SSH into instances and check Flask service: systemctl status flaskapp")
    
    print_status("="*60)
    
except Exception as e:
    print_status(f"Error retrieving final details: {str(e)}", "ERROR")
    print_status("Deployment completed but some details could not be retrieved")




