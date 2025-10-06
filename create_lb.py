#!/usr/bin/env python3
"""
AWS Load Balancer Infrastructure Creation Script - Complete Refactored Version

This script creates a complete AWS infrastructure including:
- Custom VPC with subnets in different AZs
- Internet Gateway with routing
- Security Groups for LB and EC2 instances
- EC2 instances with Flask web servers
- Application Load Balancer with target groups
- Automated testing with curl verification

The script is idempotent and can be run multiple times safely.
All resource creation is broken down into individual functions for better organization.
"""

import boto3
import time
import json
import os
import requests
import argparse
import base64
from botocore.exceptions import ClientError, WaiterError

# Initialize AWS clients
ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')
elbv2 = boto3.client('elbv2')
autoscaling = boto3.client('autoscaling')
cloudwatch = boto3.client('cloudwatch')
iam = boto3.client('iam')

# Get current AWS region
session = boto3.Session()
current_region = session.region_name
if not current_region:
    current_region = ec2_client.meta.region_name

# Configuration constants
PREFIX = 'coolscale'
TAG_VALUE = 'Coolscale'
LB_NAME = f'{PREFIX}-lb'
LB_SG_NAME = f'{PREFIX}-lb-sg'
INSTANCE_SG_NAME = f'{PREFIX}-instance-sg'
TG_NAME = f'{PREFIX}-tg'
KEY_NAME = f'{PREFIX}-key'
VPC_NAME = f'{PREFIX}-vpc'
IGW_NAME = f'{PREFIX}-igw'

# Auto Scaling constants
LT_NAME = f'{PREFIX}-lt'
ASG_NAME = f'{PREFIX}-asg'
SCALE_UP_ALARM_NAME = f'{PREFIX}-scale-up'
SCALE_DOWN_ALARM_NAME = f'{PREFIX}-scale-down'
# Auto Scaling Group Configuration
MAX_INSTANCES = 3  # Maximum number of instances in the Auto Scaling Group
MIN_INSTANCES = 2  # Minimum number of instances in the Auto Scaling Group
DESIRED_INSTANCES = 2  # Desired number of instances in the Auto Scaling Group

# Global variables to store created resources
vpc = None
vpc_id = None
selected_subnets = []
subnet_ids = []
igw = None
igw_id = None
custom_route_table = None
lb_sg = None
instance_sg = None
key_path = f'./{KEY_NAME}.pem'
ami = None
instances = []
instance_ids = []
elastic_ips = []
elastic_ip_allocation_ids = []
tg_arn = None
lb_arn = None
dns_name = None
listener_arn = None

# Auto Scaling variables
launch_template = None
launch_template_id = None
asg_arn = None
asg_name = None

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

def validate_aws_region():
    """Validate AWS region availability"""
    global current_region
    
    print_status("Starting infrastructure deployment...")
    print_status(f"Current AWS Region: {current_region}")
    print_status(f"All resources will be created in region: {current_region}")

    if not current_region:
        print_status("ERROR: Could not determine AWS region", "ERROR")
        print_status("Please ensure AWS credentials are configured and region is set", "ERROR")
        raise Exception("AWS region not detected. Please configure AWS credentials and region.")

def create_vpc():
    """Create or retrieve existing VPC"""
    global vpc, vpc_id
    
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

def create_subnets():
    """Create subnets in different availability zones"""
    global selected_subnets, subnet_ids
    
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
        subnet_cidrs = ['10.0.1.0/24', '10.0.2.0/24']
        
        for i, az in enumerate(available_azs[:2]):
            subnet_name = f"{PREFIX}-subnet-{az}"
            
            # Check if subnet already exists
            existing_subnet = next((s for s in existing_subnets if s.availability_zone == az), None)
            
            if existing_subnet:
                print_status(f"Using existing subnet {existing_subnet.id} in AZ {az}")
                selected_subnets.append(existing_subnet)
            else:
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
        
        subnet_ids = [s.id for s in selected_subnets]
        print_status(f"Successfully created/selected 2 subnets: {subnet_ids}")
        print_status(f"Using AZs: {[s.availability_zone for s in selected_subnets]}")
        
    except Exception as e:
        print_status(f"Failed to create subnets: {str(e)}", "ERROR")
        raise

def create_internet_gateway():
    """Create Internet Gateway and configure routing"""
    global igw, igw_id
    
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
        
        # Configure routing
        configure_route_table()
        configure_subnets()
        
    except Exception as e:
        print_status(f"Failed to configure Internet Gateway and routing: {str(e)}", "ERROR")
        raise

def configure_route_table():
    """Create and configure custom route table for Internet access"""
    global custom_route_table
    
    print_status("Creating and configuring custom route table for Internet access...")
    
    route_table_name = f"{PREFIX}-rt"
    
    try:
        # Check if custom route table already exists
        existing_route_tables = list(ec2.route_tables.filter(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'tag:Name', 'Values': [route_table_name]}
            ]
        ))
        
        if existing_route_tables:
            custom_route_table = existing_route_tables[0]
            print_status(f"Found existing custom route table: {custom_route_table.id}")
        else:
            # Create new custom route table
            custom_route_table = ec2.create_route_table(
                VpcId=vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'route-table',
                    'Tags': [
                        {'Key': 'Name', 'Value': route_table_name},
                        {'Key': 'Project', 'Value': TAG_VALUE}
                    ]
                }]
            )
            print_status(f"Created custom route table: {custom_route_table.id}")
        
        # Check existing routes in the custom route table
        existing_routes = list(custom_route_table.routes)
        print_status(f"Custom route table has {len(existing_routes)} existing routes")
        
        # Remove any blackhole routes for 0.0.0.0/0
        blackhole_routes_removed = 0
        for route in existing_routes:
            if (route.destination_cidr_block == '0.0.0.0/0' and 
                hasattr(route, 'gateway_id') and 
                route.gateway_id == 'local'):
                # This is a blackhole route, remove it
                try:
                    custom_route_table.delete_route(DestinationCidrBlock='0.0.0.0/0')
                    print_status("Removed blackhole route for 0.0.0.0/0")
                    blackhole_routes_removed += 1
                except ClientError as e:
                    print_status(f"Warning: Could not remove blackhole route: {str(e)}", "WARNING")
        
        if blackhole_routes_removed > 0:
            print_status(f"Removed {blackhole_routes_removed} blackhole routes")
        
        # Check if proper route to Internet Gateway exists
        igw_route_exists = False
        for route in existing_routes:
            if (route.destination_cidr_block == '0.0.0.0/0' and 
                hasattr(route, 'gateway_id') and 
                route.gateway_id == igw_id):
                igw_route_exists = True
                print_status("Route to Internet Gateway already exists and is properly configured")
                break
        
        # Add route to Internet Gateway if it doesn't exist
        if not igw_route_exists:
            try:
                custom_route_table.create_route(
                    DestinationCidrBlock='0.0.0.0/0',
                    GatewayId=igw_id
                )
                print_status("Added route to Internet Gateway in custom route table")
            except ClientError as e:
                if 'RouteAlreadyExists' in str(e):
                    print_status("Route to Internet Gateway already exists")
                else:
                    print_status(f"Failed to add route: {str(e)}", "ERROR")
                    raise
        else:
            print_status("Route to Internet Gateway is properly configured")
            
    except Exception as e:
        print_status(f"Failed to configure custom route table: {str(e)}", "ERROR")
        raise

def configure_subnets():
    """Configure subnets for public IP assignment and associate with custom route table"""
    print_status("Associating subnets with custom route table...")
    
    for subnet in selected_subnets:
        # Check if subnet is already associated with our custom route table
        current_association = None
        for association in custom_route_table.associations:
            if association.subnet_id == subnet.id:
                current_association = association
                break
        
        if current_association:
            print_status(f"Subnet {subnet.id} is already associated with custom route table {custom_route_table.id}")
        else:
            # Associate subnet with custom route table
            try:
                custom_route_table.associate_with_subnet(SubnetId=subnet.id)
                print_status(f"Associated subnet {subnet.id} with custom route table {custom_route_table.id}")
            except ClientError as e:
                print_status(f"Failed to associate subnet {subnet.id} with custom route table: {str(e)}", "ERROR")
                raise
    
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

def create_security_groups():
    """Create security groups for LB and EC2 instances"""
    global lb_sg, instance_sg
    
    # Create LB Security Group
    print_status(f"Checking for existing security group: {LB_SG_NAME}")
    try:
        # Check if LB security group already exists
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

    # Create Instance Security Group
    print_status(f"Checking for existing security group: {INSTANCE_SG_NAME}")
    try:
        # Check if instance security group already exists
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

def create_key_pair():
    """Create key pair and save PEM file"""
    global key_path
    
    print_status(f"Checking for existing key pair: {KEY_NAME}")
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

def find_ami():
    """Find latest Amazon Linux 2 AMI"""
    global ami
    
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

def get_user_data_script():
    """Create user data script for Flask web server"""
    return '''#!/bin/bash
# Update system
yum update -y

# Install Python3 and pip
yum install -y python3 python3-pip

# Install Flask with compatible urllib3 version
pip3 install flask requests 'urllib3<2.0'

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
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

# HTML template with CSS styling
def get_html_template():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CS218 Load Balancer Demo</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            margin: 10px 0 0 0;
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .status-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
            border-left: 5px solid #4facfe;
        }
        
        .status-card h2 {
            margin: 0 0 15px 0;
            color: #4facfe;
            font-size: 1.5em;
        }
        
        .status-success {
            background: #d4edda;
            border-left-color: #28a745;
            color: #155724;
        }
        
        .status-success h2 {
            color: #28a745;
        }
        
        .json-container {
            background: #2d3748;
            border-radius: 10px;
            padding: 25px;
            margin: 20px 0;
            overflow-x: auto;
        }
        
        .json-content {
            color: #e2e8f0;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.6;
            white-space: pre-wrap;
        }
        
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .metadata-item {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4facfe;
        }
        
        .metadata-item h3 {
            margin: 0 0 10px 0;
            color: #4facfe;
            font-size: 1.1em;
            text-transform: capitalize;
        }
        
        .metadata-item p {
            margin: 0;
            color: #666;
            word-break: break-all;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }
        
        .instance-badge {
            display: inline-block;
            background: #4facfe;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            margin-left: 10px;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .content {
                padding: 20px;
            }
            
            .metadata-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CS218 Load Balancer Demo <span class="instance-badge">IP: {{ instance_number }}</span></h1>
            <p>AWS Application Load Balancer with EC2 Instances</p>
        </div>
        
        <div class="content">
            <div class="status-card status-success">
                <h2>✅ Server Status</h2>
                <p><strong>Message:</strong> {{ message }}</p>
                <p><strong>Hostname:</strong> {{ hostname }}</p>
                <p><strong>Local IP:</strong> {{ local_ip }}</p>
            </div>
            
            <div class="status-card">
                <h2>📊 Instance Metadata</h2>
                <div class="metadata-grid">
                    {% for key, value in metadata.items() %}
                    <div class="metadata-item">
                        <h3>{{ key.replace('-', ' ').title() }}</h3>
                        <p>{{ value }}</p>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <div class="status-card">
                <h2>🔍 Raw JSON Response</h2>
                <div class="json-container">
                    <div class="json-content">{{ json_data }}</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>CS218 Load Balancer Demo | AWS EC2 Instance | Flask Application</p>
        </div>
    </div>
</body>
</html>"""

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
        
        # Create response data
        response_data = {
            'hostname': hostname,
            'local_ip': local_ip,
            'metadata': metadata,
            'message': 'Flask server running successfully!'
        }
        
        # Use private IP as instance identifier (unique and auto-scaling friendly)
        instance_number = local_ip
        
        # Pretty print JSON for display
        json_data = json.dumps(response_data, indent=2)
        
        # Render HTML template
        return render_template_string(get_html_template(), 
                                    message=response_data['message'],
                                    hostname=hostname,
                                    local_ip=local_ip,
                                    metadata=metadata,
                                    json_data=json_data,
                                    instance_number=instance_number)
        
    except Exception as e:
        error_data = {'error': str(e)}
        return render_template_string(get_html_template(), 
                                    message="Error occurred",
                                    hostname="Unknown",
                                    local_ip="Unknown",
                                    metadata={},
                                    json_data=json.dumps(error_data, indent=2),
                                    instance_number="Unknown")

@app.route('/api')
def api_info():
    """API endpoint that returns raw JSON (for curl testing)"""
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
User=root
WorkingDirectory=/var/www/flaskapp
Environment=PATH=/usr/bin:/usr/local/bin
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Change ownership of the app directory to root (since service runs as root)
chown -R root:root /var/www/flaskapp

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
    journalctl -u flaskapp --no-pager -n 20
    echo "Attempting to fix urllib3 compatibility issue..."
    pip3 install 'urllib3<2.0' --upgrade --force-reinstall
    systemctl restart flaskapp
    sleep 5
    if systemctl is-active --quiet flaskapp; then
        echo "Flask app started successfully after urllib3 fix"
    else
        echo "Flask app still failing after urllib3 fix:"
        journalctl -u flaskapp --no-pager -n 10
    fi
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
echo "Python packages installed:" >> /var/log/user-data.log
pip3 list | grep -E "(flask|requests|urllib3)" >> /var/log/user-data.log 2>&1 || true
'''

def create_ec2_instances():
    """Launch two EC2 instances in different AZs"""
    global instances, instance_ids
    
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
                    UserData=get_user_data_script(),
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
                    UserData=get_user_data_script(),
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

def create_and_attach_elastic_ips():
    """Create and attach Elastic IPs to EC2 instances"""
    global elastic_ips, elastic_ip_allocation_ids
    
    print_status("="*60)
    print_status("CREATING AND ATTACHING ELASTIC IPs TO EC2 INSTANCES", "INFO")
    print_status("="*60)
    
    try:
        elastic_ips = []
        elastic_ip_allocation_ids = []
        
        for i, instance in enumerate(instances, 1):
            print_status(f"Processing instance {i}: {instance.id}")
            
            # Check if instance already has an Elastic IP
            existing_eips = ec2_client.describe_addresses(
                Filters=[{'Name': 'instance-id', 'Values': [instance.id]}]
            )
            
            if existing_eips['Addresses']:
                eip = existing_eips['Addresses'][0]
                print_status(f"Instance {i} already has Elastic IP: {eip['PublicIp']}")
                elastic_ips.append(eip)
                elastic_ip_allocation_ids.append(eip['AllocationId'])
                continue
            
            # Create new Elastic IP
            print_status(f"Creating Elastic IP for instance {i}...")
            eip_response = ec2_client.allocate_address(
                Domain='vpc',
                TagSpecifications=[{
                    'ResourceType': 'elastic-ip',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'{PREFIX}-eip-instance-{i}'},
                        {'Key': 'Project', 'Value': TAG_VALUE},
                        {'Key': 'InstanceId', 'Value': instance.id}
                    ]
                }]
            )
            
            allocation_id = eip_response['AllocationId']
            public_ip = eip_response['PublicIp']
            
            print_status(f"Created Elastic IP: {public_ip} (Allocation ID: {allocation_id})")
            
            # Attach Elastic IP to instance
            print_status(f"Attaching Elastic IP to instance {i}...")
            ec2_client.associate_address(
                InstanceId=instance.id,
                AllocationId=allocation_id
            )
            
            print_status(f"Successfully attached Elastic IP {public_ip} to instance {i}")
            elastic_ips.append(eip_response)
            elastic_ip_allocation_ids.append(allocation_id)
            
            # Wait a moment for the association to complete
            time.sleep(5)
        
        print_status(f"Created/attached {len(elastic_ips)} Elastic IPs to instances")
        
        # Wait for Elastic IPs to be fully associated
        print_status("Waiting for Elastic IPs to be fully associated...")
        time.sleep(10)
        
        # Reload instances to get updated public IP information
        for instance in instances:
            instance.reload()
            
        print_status("Elastic IP setup completed successfully!")
        
    except Exception as e:
        print_status(f"Error creating/attaching Elastic IPs to instances: {str(e)}", "ERROR")
        raise

def create_target_group():
    """Create target group for load balancer"""
    global tg_arn
    
    print_status(f"Checking for existing target group: {TG_NAME}")
    try:
        # Check if target group already exists
        try:
            tg_response = elbv2.describe_target_groups(Names=[TG_NAME])
            tg_arn = tg_response['TargetGroups'][0]['TargetGroupArn']
            print_status(f"Found existing target group: {TG_NAME} (ARN: {tg_arn})")
            
            # Check if instances are already registered
            registered_targets = elbv2.describe_target_health(TargetGroupArn=tg_arn)
            current_target_ids = [target['Target']['Id'] for target in registered_targets['TargetHealthDescriptions']]
            
            # Register any new instances (only if instances exist)
            if instances:
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
            else:
                print_status("No manual instances to register (auto scaling mode)")
                
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

                # Register EC2 instances to target group (only if instances exist)
                if instances:
                    print_status("Registering EC2 instances with target group...")
                    elbv2.register_targets(
                        TargetGroupArn=tg_arn,
                        Targets=[{'Id': i.id} for i in instances]
                    )
                    print_status(f"Registered {len(instances)} instances with target group")
                else:
                    print_status("No manual instances to register (auto scaling mode)")
            else:
                raise
                
    except Exception as e:
        print_status(f"Failed to create/retrieve target group: {str(e)}", "ERROR")
        raise

def create_load_balancer():
    """Create Application Load Balancer"""
    global lb_arn, dns_name
    
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

def create_listener():
    """Create listener for HTTP traffic"""
    global listener_arn
    
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

def pretty_print_results():
    """Pretty print all resource details"""
    print_status("Deployment completed successfully! Gathering resource details...")

    def pretty_print(title, data):
        print(f"\n{'='*10} {title} {'='*10}")
        print(json.dumps(data, indent=2, default=str))

    try:
        # Load Balancer details
        print_status("Retrieving load balancer details...")
        lb_details = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]
        pretty_print("Load Balancer", lb_details)

        # EC2 Instances details (only if instances exist)
        if instances:
            print_status("Retrieving EC2 instance details...")
            instance_details = [ec2_client.describe_instances(InstanceIds=[i.id])['Reservations'][0]['Instances'][0] for i in instances]
            pretty_print("EC2 Instances", instance_details)
        else:
            print_status("No manual instances to retrieve (auto scaling mode)")
            instance_details = []
        
        # Generate SSH commands for each instance with Elastic IP information
        if instance_details:
            print_status("="*60)
            print_status("SSH COMMANDS FOR EC2 INSTANCES (WITH ELASTIC IPs)", "INFO")
            print_status("="*60)
            for i, instance_detail in enumerate(instance_details, 1):
                public_ip = instance_detail.get('PublicIpAddress', 'N/A')
                instance_id = instance_detail['InstanceId']
                az = instance_detail['Placement']['AvailabilityZone']
            
                # Get Elastic IP information if available
                elastic_ip_info = ""
                if i <= len(elastic_ips):
                    eip = elastic_ips[i-1]
                    elastic_ip_info = f" (Elastic IP: {eip['PublicIp']})"
                
                if public_ip != 'N/A':
                    ssh_command = f"ssh -i {key_path} ec2-user@{public_ip}"
                    print_status(f"Instance {i} ({instance_id}) in {az}:")
                    print_status(f"  Public IP: {public_ip}{elastic_ip_info}")
                    print_status(f"  SSH Command: {ssh_command}")
                    print_status("")
                else:
                    print_status(f"Instance {i} ({instance_id}) in {az}:")
                    print_status(f"  Public IP: Not available yet{elastic_ip_info}")
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
        
        # Check if auto scaling is enabled
        if asg_arn:
            print_status(f"Auto Scaling Group ARN: {asg_arn}")
            print_status(f"Launch Template ID: {launch_template_id}")
            print_status(f"Auto Scaling: Min={MIN_INSTANCES}, Max={MAX_INSTANCES}, Desired={DESIRED_INSTANCES}")
            print_status(f"Scale Up Alarm: {SCALE_UP_ALARM_NAME}")
            print_status(f"Scale Down Alarm: {SCALE_DOWN_ALARM_NAME}")
        else:
            print_status(f"EC2 Instance IDs: {instance_ids}")
            print_status(f"Elastic IPs: {len(elastic_ips)} created/attached")
        
        print_status(f"PEM file location: {key_path}")
        print_status("")
        
        # Only show Elastic IP summary if not using auto scaling
        if not asg_arn and elastic_ips:
            print_status("ELASTIC IP SUMMARY:")
            for i, eip in enumerate(elastic_ips, 1):
                print_status(f"  Instance {i}: {eip['PublicIp']} (Allocation ID: {eip['AllocationId']})")
            print_status("")
        # Only show SSH commands if not using auto scaling
        if not asg_arn and instance_details:
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
        else:
            print_status("SSH ACCESS (Auto Scaling):")
            print_status(f"  Note: Auto scaling instances use dynamic IPs")
            print_status(f"  Use AWS Console or 'aws ec2 describe-instances' to get current IPs")
            print_status(f"  SSH command: ssh -i {key_path} ec2-user@<dynamic-ip>")
        print_status("")
        print_status("TESTING COMMANDS:")
        print_status(f"  Test Flask app: curl http://{dns_name}")
        
        if not asg_arn:
            print_status(f"  Test specific instance: curl http://<instance-public-ip>")
            if elastic_ips:
                print_status("  Test with Elastic IPs:")
                for i, eip in enumerate(elastic_ips, 1):
                    print_status(f"    Instance {i}: curl http://{eip['PublicIp']}")
        else:
            print_status("  Auto Scaling: Test via load balancer DNS only")
            print_status("  Individual instances have dynamic IPs")
        print_status("="*60)
        print_status("You can now access your Flask application via the load balancer DNS name!")
        print_status("Each request will show which instance is serving the request.")
        
        if not asg_arn:
            print_status("Elastic IPs provide static IP addresses that won't change on instance restart.")
        else:
            print_status("Auto scaling will automatically adjust the number of instances based on CPU usage.")
            print_status(f"Instances will scale up when CPU > 75% and scale down when CPU < 30%.")
            print_status(f"Instance range: {MIN_INSTANCES} to {MAX_INSTANCES} instances.")
        
    except Exception as e:
        print_status(f"Error retrieving final details: {str(e)}", "ERROR")
        print_status("Deployment completed but some details could not be retrieved")

def test_load_balancer():
    """Test the load balancer with curl"""
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

def create_launch_template():
    """Create launch template for auto scaling"""
    global launch_template, launch_template_id
    
    print_status(f"Checking for existing launch template: {LT_NAME}")
    
    # Validate that IAM instance profile exists
    instance_profile_name = f'{PREFIX}-instance-profile'
    try:
        iam.get_instance_profile(InstanceProfileName=instance_profile_name)
        print_status(f"Verified IAM instance profile exists: {instance_profile_name}")
    except ClientError as e:
        print_status(f"Error: IAM instance profile {instance_profile_name} not found", "ERROR")
        raise Exception(f"IAM instance profile {instance_profile_name} must be created before launch template")
    
    try:
        # Check if launch template already exists
        try:
            lt_response = ec2_client.describe_launch_templates(
                LaunchTemplateNames=[LT_NAME]
            )
            launch_template_id = lt_response['LaunchTemplates'][0]['LaunchTemplateId']
            print_status(f"Found existing launch template: {LT_NAME} (ID: {launch_template_id})")
        except ClientError as e:
            if 'InvalidLaunchTemplateName.NotFound' in str(e):
                # Launch template doesn't exist, create it
                print_status(f"Creating launch template: {LT_NAME}")
                
                # Create launch template with base64-encoded user data
                user_data_script = get_user_data_script()
                user_data_encoded = base64.b64encode(user_data_script.encode('utf-8')).decode('utf-8')
                
                lt_response = ec2_client.create_launch_template(
                    LaunchTemplateName=LT_NAME,
                    LaunchTemplateData={
                        'ImageId': ami,
                        'InstanceType': 't2.micro',
                        'KeyName': KEY_NAME,
                        'UserData': user_data_encoded,
                        'SecurityGroupIds': [instance_sg.id],
                        'TagSpecifications': [{
                            'ResourceType': 'instance',
                            'Tags': [
                                {'Key': 'Name', 'Value': f'{PREFIX}-asg-instance'},
                                {'Key': 'Project', 'Value': TAG_VALUE},
                                {'Key': 'AutoScaling', 'Value': 'true'}
                            ]
                        }],
                        'IamInstanceProfile': {
                            'Name': f'{PREFIX}-instance-profile'
                        }
                    },
                    TagSpecifications=[{
                        'ResourceType': 'launch-template',
                        'Tags': [
                            {'Key': 'Name', 'Value': LT_NAME},
                            {'Key': 'Project', 'Value': TAG_VALUE}
                        ]
                    }]
                )
                launch_template_id = lt_response['LaunchTemplate']['LaunchTemplateId']
                print_status(f"Created launch template: {LT_NAME} (ID: {launch_template_id})")
            else:
                raise
                
    except Exception as e:
        print_status(f"Failed to create/retrieve launch template: {str(e)}", "ERROR")
        raise

def create_auto_scaling_group():
    """Create auto scaling group"""
    global asg_arn, asg_name
    
    print_status(f"Checking for existing auto scaling group: {ASG_NAME}")
    try:
        # Check if auto scaling group already exists
        try:
            asg_response = autoscaling.describe_auto_scaling_groups(
                AutoScalingGroupNames=[ASG_NAME]
            )
            if asg_response['AutoScalingGroups']:
                asg_arn = asg_response['AutoScalingGroups'][0]['AutoScalingGroupARN']
                asg_name = asg_response['AutoScalingGroups'][0]['AutoScalingGroupName']
                print_status(f"Found existing auto scaling group: {ASG_NAME} (ARN: {asg_arn})")
            else:
                raise ClientError({'Error': {'Code': 'AutoScalingGroupNotFound', 'Message': 'Not found'}}, 'DescribeAutoScalingGroups')
        except ClientError as e:
            if 'AutoScalingGroupNotFound' in str(e):
                # Auto scaling group doesn't exist, create it
                print_status(f"Creating auto scaling group: {ASG_NAME}")
                
                asg_response = autoscaling.create_auto_scaling_group(
                    AutoScalingGroupName=ASG_NAME,
                    LaunchTemplate={
                        'LaunchTemplateId': launch_template_id,
                        'Version': '$Latest'
                    },
                    MinSize=MIN_INSTANCES,
                    MaxSize=MAX_INSTANCES,
                    DesiredCapacity=DESIRED_INSTANCES,
                    TargetGroupARNs=[tg_arn],
                    VPCZoneIdentifier=','.join(subnet_ids),
                    Tags=[
                        {
                            'Key': 'Name',
                            'Value': ASG_NAME,
                            'PropagateAtLaunch': False
                        },
                        {
                            'Key': 'Project',
                            'Value': TAG_VALUE,
                            'PropagateAtLaunch': False
                        }
                    ]
                )
                asg_name = ASG_NAME
                print_status(f"Created auto scaling group: {ASG_NAME}")
                
                # Wait for instances to be launched
                print_status("Waiting for auto scaling group instances to launch...")
                time.sleep(30)
                
                # Get the ARN
                asg_details = autoscaling.describe_auto_scaling_groups(
                    AutoScalingGroupNames=[ASG_NAME]
                )
                asg_arn = asg_details['AutoScalingGroups'][0]['AutoScalingGroupARN']
                
            else:
                raise
                
    except Exception as e:
        print_status(f"Failed to create/retrieve auto scaling group: {str(e)}", "ERROR")
        raise

def create_scaling_policies():
    """Create scaling policies for auto scaling group"""
    print_status("Creating scaling policies for auto scaling...")
    
    # Validate that required variables are set
    if not asg_name:
        print_status("Error: Auto Scaling Group name not available", "ERROR")
        raise Exception("Auto Scaling Group name not available. Cannot create scaling policies.")
    
    try:
        # Create scale-up policy
        scale_up_policy_name = f'{PREFIX}-scale-up-policy'
        print_status(f"Creating scale-up policy: {scale_up_policy_name}")
        
        scale_up_response = autoscaling.put_scaling_policy(
            AutoScalingGroupName=asg_name,
            PolicyName=scale_up_policy_name,
            PolicyType='SimpleScaling',
            AdjustmentType='ChangeInCapacity',
            ScalingAdjustment=1,
            Cooldown=300  # 5 minutes cooldown
        )
        scale_up_policy_arn = scale_up_response['PolicyARN']
        print_status(f"Created scale-up policy: {scale_up_policy_arn}")
        
        # Create scale-down policy
        scale_down_policy_name = f'{PREFIX}-scale-down-policy'
        print_status(f"Creating scale-down policy: {scale_down_policy_name}")
        
        scale_down_response = autoscaling.put_scaling_policy(
            AutoScalingGroupName=asg_name,
            PolicyName=scale_down_policy_name,
            PolicyType='SimpleScaling',
            AdjustmentType='ChangeInCapacity',
            ScalingAdjustment=-1,
            Cooldown=300  # 5 minutes cooldown
        )
        scale_down_policy_arn = scale_down_response['PolicyARN']
        print_status(f"Created scale-down policy: {scale_down_policy_arn}")
        
        print_status("Note: Scaling policies are identified by name and associated with Auto Scaling Group")
        
        return scale_up_policy_arn, scale_down_policy_arn
        
    except Exception as e:
        print_status(f"Failed to create scaling policies: {str(e)}", "ERROR")
        raise

def create_cloudwatch_alarms():
    """Create CloudWatch alarms for auto scaling"""
    print_status("Creating CloudWatch alarms for auto scaling...")
    
    # Validate that required variables are set
    if not asg_name:
        print_status("Error: Auto Scaling Group name not available", "ERROR")
        raise Exception("Auto Scaling Group name not available. Cannot create CloudWatch alarms.")
    
    try:
        # Create scaling policies first
        scale_up_policy_arn, scale_down_policy_arn = create_scaling_policies()
        
        # Create scale-up alarm (CPU > 75%)
        print_status(f"Creating scale-up alarm: {SCALE_UP_ALARM_NAME}")
        cloudwatch.put_metric_alarm(
            AlarmName=SCALE_UP_ALARM_NAME,
            ComparisonOperator='GreaterThanThreshold',
            EvaluationPeriods=2,
            MetricName='CPUUtilization',
            Namespace='AWS/EC2',
            Period=60,
            Statistic='Average',
            Threshold=75.0,
            ActionsEnabled=True,
            AlarmActions=[scale_up_policy_arn],
            AlarmDescription='Scale up when CPU utilization is greater than 75%',
            Dimensions=[
                {
                    'Name': 'AutoScalingGroupName',
                    'Value': asg_name
                }
            ],
            Tags=[
                {'Key': 'Name', 'Value': SCALE_UP_ALARM_NAME},
                {'Key': 'Project', 'Value': TAG_VALUE}
            ]
        )
        print_status(f"Created scale-up alarm: {SCALE_UP_ALARM_NAME}")
        
        # Create scale-down alarm (CPU < 30%)
        print_status(f"Creating scale-down alarm: {SCALE_DOWN_ALARM_NAME}")
        cloudwatch.put_metric_alarm(
            AlarmName=SCALE_DOWN_ALARM_NAME,
            ComparisonOperator='LessThanThreshold',
            EvaluationPeriods=2,
            MetricName='CPUUtilization',
            Namespace='AWS/EC2',
            Period=60,
            Statistic='Average',
            Threshold=30.0,
            ActionsEnabled=True,
            AlarmActions=[scale_down_policy_arn],
            AlarmDescription='Scale down when CPU utilization is less than 30%',
            Dimensions=[
                {
                    'Name': 'AutoScalingGroupName',
                    'Value': asg_name
                }
            ],
            Tags=[
                {'Key': 'Name', 'Value': SCALE_DOWN_ALARM_NAME},
                {'Key': 'Project', 'Value': TAG_VALUE}
            ]
        )
        print_status(f"Created scale-down alarm: {SCALE_DOWN_ALARM_NAME}")
        
    except Exception as e:
        print_status(f"Failed to create CloudWatch alarms: {str(e)}", "ERROR")
        raise

def create_iam_instance_profile():
    """Create IAM instance profile for auto scaling instances"""
    print_status("Creating IAM instance profile for auto scaling...")
    
    try:
        profile_name = f'{PREFIX}-instance-profile'
        
        # Check if instance profile already exists
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            print_status(f"Found existing instance profile: {profile_name}")
        except ClientError as e:
            if 'NoSuchEntity' in str(e):
                # Create IAM role for EC2 instances
                role_name = f'{PREFIX}-ec2-role'
                try:
                    iam.get_role(RoleName=role_name)
                    print_status(f"Found existing IAM role: {role_name}")
                except ClientError:
                    print_status(f"Creating IAM role: {role_name}")
                    iam.create_role(
                        RoleName=role_name,
                        AssumeRolePolicyDocument=json.dumps({
                            'Version': '2012-10-17',
                            'Statement': [{
                                'Effect': 'Allow',
                                'Principal': {'Service': 'ec2.amazonaws.com'},
                                'Action': 'sts:AssumeRole'
                            }]
                        }),
                        Tags=[
                            {'Key': 'Name', 'Value': role_name},
                            {'Key': 'Project', 'Value': TAG_VALUE}
                        ]
                    )
                    
                    # Attach CloudWatch agent policy
                    iam.attach_role_policy(
                        RoleName=role_name,
                        PolicyArn='arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy'
                    )
                    print_status(f"Created IAM role: {role_name}")
                
                # Create instance profile
                print_status(f"Creating instance profile: {profile_name}")
                iam.create_instance_profile(
                    InstanceProfileName=profile_name,
                    Tags=[
                        {'Key': 'Name', 'Value': profile_name},
                        {'Key': 'Project', 'Value': TAG_VALUE}
                    ]
                )
                
                # Add role to instance profile
                iam.add_role_to_instance_profile(
                    InstanceProfileName=profile_name,
                    RoleName=role_name
                )
                print_status(f"Created instance profile: {profile_name}")
                
                # Wait a moment for IAM propagation
                print_status("Waiting for IAM instance profile to propagate...")
                time.sleep(10)
                
                # Verify the instance profile was created successfully
                try:
                    iam.get_instance_profile(InstanceProfileName=profile_name)
                    print_status(f"Verified instance profile creation: {profile_name}")
                except ClientError as e:
                    print_status(f"Error verifying instance profile creation: {str(e)}", "ERROR")
                    raise Exception(f"Failed to verify IAM instance profile {profile_name} creation")
            else:
                raise
                
    except Exception as e:
        print_status(f"Failed to create IAM instance profile: {str(e)}", "ERROR")
        raise

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Create AWS Load Balancer Infrastructure with optional Auto Scaling'
    )
    parser.add_argument(
        '--enable-autoscaling',
        action='store_true',
        help=f'Enable auto scaling for the load balancer (min: {MIN_INSTANCES}, max: {MAX_INSTANCES} instances)'
    )
    return parser.parse_args()

if __name__ == "__main__":
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Step 1: Validate AWS region
        validate_aws_region()
        
        # Step 2: Create basic infrastructure
        create_vpc()
        create_subnets()
        create_internet_gateway()
        
        # Step 3: Create security groups
        create_security_groups()
        
        # Step 4: Create key pair
        create_key_pair()
        
        # Step 5: Find AMI
        find_ami()
        
        # Step 6: Create IAM instance profile (for auto scaling if enabled)
        if args.enable_autoscaling:
            create_iam_instance_profile()
        
        # Step 7: Create EC2 instances (only if auto scaling is not enabled)
        if not args.enable_autoscaling:
            create_ec2_instances()
            # Step 8: Create and attach Elastic IPs to instances
            create_and_attach_elastic_ips()
        
        # Step 9: Create target group
        create_target_group()
        
        # Step 10: Create load balancer
        create_load_balancer()
        
        # Step 11: Create listener
        create_listener()
        
        # Step 12: Create auto scaling components (if enabled)
        if args.enable_autoscaling:
            print_status("="*60)
            print_status("ENABLING AUTO SCALING", "INFO")
            print_status("="*60)
            
            # Create launch template
            create_launch_template()
            
            # Create auto scaling group
            create_auto_scaling_group()
            
            # Create CloudWatch alarms
            create_cloudwatch_alarms()
            
            print_status("="*60)
            print_status("AUTO SCALING CONFIGURATION COMPLETED", "SUCCESS")
            print_status("="*60)
            print_status(f"Auto Scaling Group: Min={MIN_INSTANCES}, Max={MAX_INSTANCES}, Desired={DESIRED_INSTANCES}")
            print_status("Scale Up: CPU > 75% for 2 periods (2 minutes)")
            print_status("Scale Down: CPU < 30% for 2 periods (2 minutes)")
            print_status("="*60)
        
        # Step 13: Wait for LB to be active
        print_status("Waiting for load balancer to become active...")
        if not wait_for_resource(elbv2.get_waiter('load_balancer_available'), LoadBalancerArns=[lb_arn]):
            print_status("Failed to wait for load balancer to become active", "ERROR")
            raise Exception("Load balancer failed to become active")
        print_status("Load balancer is now active and ready to serve traffic")
        
        # Step 14: Pretty print results
        pretty_print_results()
        
        # Step 15: Test the load balancer
        test_load_balancer()
        
    except Exception as e:
        print_status(f"Infrastructure setup failed: {str(e)}", "ERROR")
        raise
