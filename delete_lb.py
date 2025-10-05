#!/usr/bin/env python3
"""
Delete Load Balancer Infrastructure Script

This script tears down all AWS resources created by create_lb.py.
It identifies resources using the 'Coolscale' tag and deletes them in the proper order.

Resources deleted in order:
1. Load Balancer (must be deleted first)
2. Target Groups
3. EC2 Instances
4. Security Groups
5. Key Pairs (optional - asks for confirmation)
6. Local PEM file (optional - asks for confirmation)
"""

import boto3
import time
import json
import os
from botocore.exceptions import ClientError, WaiterError

# Initialize AWS clients
ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')
elbv2 = boto3.client('elbv2')

# Configuration
TAG_KEY = 'Project'
TAG_VALUE = 'Coolscale'
PREFIX = 'coolscale'
KEY_NAME = f'{PREFIX}-key'
KEY_PATH = f'./{KEY_NAME}.pem'

def print_status(message, status="INFO"):
    """Print status messages with timestamps"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{status}] {message}")

def wait_for_resource_deletion(waiter, **kwargs):
    """Generic function to wait for AWS resources to be deleted"""
    try:
        waiter.wait(**kwargs)
        return True
    except WaiterError as e:
        if "ResourceNotFound" in str(e) or "does not exist" in str(e):
            return True  # Resource already deleted
        print_status(f"Waiter error: {str(e)}", "ERROR")
        return False
    except Exception as e:
        print_status(f"Unexpected error during wait: {str(e)}", "ERROR")
        return False

def find_resources_by_tag(tag_key, tag_value):
    """Find resources by tag key-value pair"""
    resources = {
        'load_balancers': [],
        'target_groups': [],
        'instances': [],
        'security_groups': [],
        'key_pairs': [],
        'vpcs': [],
        'subnets': [],
        'internet_gateways': []
    }
    
    try:
        # Find Load Balancers
        print_status(f"Searching for load balancers with tag {tag_key}={tag_value}...")
        lb_response = elbv2.describe_load_balancers()
        for lb in lb_response['LoadBalancers']:
            try:
                tags_response = elbv2.describe_tags(ResourceArns=[lb['LoadBalancerArn']])
                for tag_desc in tags_response['TagDescriptions']:
                    for tag in tag_desc['Tags']:
                        if tag['Key'] == tag_key and tag['Value'] == tag_value:
                            resources['load_balancers'].append(lb)
                            print_status(f"Found load balancer: {lb['LoadBalancerName']} ({lb['LoadBalancerArn']})")
            except ClientError as e:
                print_status(f"Error checking load balancer tags: {str(e)}", "WARNING")
        
        # Find Target Groups
        print_status(f"Searching for target groups with tag {tag_key}={tag_value}...")
        tg_response = elbv2.describe_target_groups()
        for tg in tg_response['TargetGroups']:
            try:
                tags_response = elbv2.describe_tags(ResourceArns=[tg['TargetGroupArn']])
                for tag_desc in tags_response['TagDescriptions']:
                    for tag in tag_desc['Tags']:
                        if tag['Key'] == tag_key and tag['Value'] == tag_value:
                            resources['target_groups'].append(tg)
                            print_status(f"Found target group: {tg['TargetGroupName']} ({tg['TargetGroupArn']})")
            except ClientError as e:
                print_status(f"Error checking target group tags: {str(e)}", "WARNING")
        
        # Find EC2 Instances
        print_status(f"Searching for EC2 instances with tag {tag_key}={tag_value}...")
        instances = ec2.instances.filter(
            Filters=[
                {'Name': f'tag:{tag_key}', 'Values': [tag_value]},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']}
            ]
        )
        for instance in instances:
            resources['instances'].append(instance)
            print_status(f"Found EC2 instance: {instance.id} (State: {instance.state['Name']})")
        
        # Find Security Groups
        print_status(f"Searching for security groups with tag {tag_key}={tag_value}...")
        security_groups = ec2_client.describe_security_groups(
            Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]
        )
        for sg in security_groups['SecurityGroups']:
            resources['security_groups'].append(sg)
            print_status(f"Found security group: {sg['GroupName']} ({sg['GroupId']})")
        
        # Find Key Pairs (by name pattern)
        print_status(f"Searching for key pairs with name pattern {PREFIX}...")
        try:
            key_pairs = ec2_client.describe_key_pairs(
                Filters=[{'Name': 'key-name', 'Values': [f'{PREFIX}-*']}]
            )
            for kp in key_pairs['KeyPairs']:
                resources['key_pairs'].append(kp)
                print_status(f"Found key pair: {kp['KeyName']}")
        except ClientError as e:
            print_status(f"Error searching for key pairs: {str(e)}", "WARNING")
        
        # Find VPCs
        print_status(f"Searching for VPCs with tag {tag_key}={tag_value}...")
        vpcs = list(ec2.vpcs.filter(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]))
        for vpc in vpcs:
            resources['vpcs'].append(vpc)
            print_status(f"Found VPC: {vpc.id}")
        
        # Find Subnets
        print_status(f"Searching for subnets with tag {tag_key}={tag_value}...")
        subnets = list(ec2.subnets.filter(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]))
        for subnet in subnets:
            resources['subnets'].append(subnet)
            print_status(f"Found subnet: {subnet.id}")
        
        # Find Internet Gateways
        print_status(f"Searching for Internet Gateways with tag {tag_key}={tag_value}...")
        igws = list(ec2.internet_gateways.filter(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]))
        for igw in igws:
            resources['internet_gateways'].append(igw)
            print_status(f"Found Internet Gateway: {igw.id}")
        
    except Exception as e:
        print_status(f"Error searching for resources: {str(e)}", "ERROR")
    
    return resources

def delete_listeners(load_balancers):
    """Delete listeners from load balancers"""
    if not load_balancers:
        return True
    
    success = True
    for lb in load_balancers:
        lb_arn = lb['LoadBalancerArn']
        lb_name = lb['LoadBalancerName']
        
        try:
            print_status(f"Deleting listeners for load balancer: {lb_name}")
            # Get all listeners for this load balancer
            listeners_response = elbv2.describe_listeners(LoadBalancerArn=lb_arn)
            
            for listener in listeners_response['Listeners']:
                listener_arn = listener['ListenerArn']
                try:
                    elbv2.delete_listener(ListenerArn=listener_arn)
                    print_status(f"Deleted listener: {listener_arn}")
                except ClientError as e:
                    print_status(f"Error deleting listener {listener_arn}: {str(e)}", "WARNING")
                    success = False
                    
        except ClientError as e:
            print_status(f"Error getting listeners for load balancer {lb_name}: {str(e)}", "WARNING")
            success = False
    
    return success

def delete_load_balancers(load_balancers):
    """Delete load balancers"""
    if not load_balancers:
        print_status("No load balancers found to delete")
        return True
    
    success = True
    for lb in load_balancers:
        lb_name = lb['LoadBalancerName']
        lb_arn = lb['LoadBalancerArn']
        
        try:
            print_status(f"Deleting load balancer: {lb_name}")
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
            print_status(f"Load balancer deletion initiated: {lb_name}")
            
            # Wait for load balancer to be deleted
            print_status(f"Waiting for load balancer {lb_name} to be deleted...")
            waiter = elbv2.get_waiter('load_balancers_deleted')
            if wait_for_resource_deletion(waiter, LoadBalancerArns=[lb_arn]):
                print_status(f"Load balancer {lb_name} deleted successfully")
            else:
                print_status(f"Failed to confirm deletion of load balancer {lb_name}", "ERROR")
                success = False
                
        except ClientError as e:
            print_status(f"Error deleting load balancer {lb_name}: {str(e)}", "ERROR")
            success = False
        except Exception as e:
            print_status(f"Unexpected error deleting load balancer {lb_name}: {str(e)}", "ERROR")
            success = False
    
    return success

def delete_target_groups(target_groups):
    """Delete target groups"""
    if not target_groups:
        print_status("No target groups found to delete")
        return True
    
    success = True
    for tg in target_groups:
        tg_name = tg['TargetGroupName']
        tg_arn = tg['TargetGroupArn']
        
        try:
            print_status(f"Deleting target group: {tg_name}")
            elbv2.delete_target_group(TargetGroupArn=tg_arn)
            print_status(f"Target group {tg_name} deleted successfully")
            
        except ClientError as e:
            if "ResourceNotFound" in str(e):
                print_status(f"Target group {tg_name} already deleted")
            else:
                print_status(f"Error deleting target group {tg_name}: {str(e)}", "ERROR")
                success = False
        except Exception as e:
            print_status(f"Unexpected error deleting target group {tg_name}: {str(e)}", "ERROR")
            success = False
    
    return success

def delete_ec2_instances(instances):
    """Terminate EC2 instances"""
    if not instances:
        print_status("No EC2 instances found to delete")
        return True
    
    instance_ids = [instance.id for instance in instances]
    
    try:
        print_status(f"Terminating EC2 instances: {instance_ids}")
        ec2_client.terminate_instances(InstanceIds=instance_ids)
        print_status("EC2 instance termination initiated")
        
        # Wait for instances to be terminated
        print_status("Waiting for EC2 instances to be terminated...")
        waiter = ec2_client.get_waiter('instance_terminated')
        if wait_for_resource_deletion(waiter, InstanceIds=instance_ids):
            print_status("All EC2 instances terminated successfully")
            return True
        else:
            print_status("Failed to confirm termination of all EC2 instances", "ERROR")
            return False
            
    except ClientError as e:
        print_status(f"Error terminating EC2 instances: {str(e)}", "ERROR")
        return False
    except Exception as e:
        print_status(f"Unexpected error terminating EC2 instances: {str(e)}", "ERROR")
        return False

def delete_security_groups(security_groups):
    """Delete security groups"""
    if not security_groups:
        print_status("No security groups found to delete")
        return True
    
    success = True
    for sg in security_groups:
        sg_name = sg['GroupName']
        sg_id = sg['GroupId']
        
        try:
            print_status(f"Deleting security group: {sg_name} ({sg_id})")
            ec2_client.delete_security_group(GroupId=sg_id)
            print_status(f"Security group {sg_name} deleted successfully")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidGroup.NotFound':
                print_status(f"Security group {sg_name} already deleted")
            elif error_code == 'DependencyViolation':
                print_status(f"Security group {sg_name} still in use, skipping deletion", "WARNING")
            else:
                print_status(f"Error deleting security group {sg_name}: {str(e)}", "ERROR")
                success = False
        except Exception as e:
            print_status(f"Unexpected error deleting security group {sg_name}: {str(e)}", "ERROR")
            success = False
    
    return success

def delete_key_pairs(key_pairs):
    """Delete key pairs"""
    if not key_pairs:
        print_status("No key pairs found to delete")
        return True
    
    success = True
    for kp in key_pairs:
        kp_name = kp['KeyName']
        
        try:
            print_status(f"Deleting key pair: {kp_name}")
            ec2_client.delete_key_pair(KeyName=kp_name)
            print_status(f"Key pair {kp_name} deleted successfully")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidKeyPair.NotFound':
                print_status(f"Key pair {kp_name} already deleted")
            else:
                print_status(f"Error deleting key pair {kp_name}: {str(e)}", "ERROR")
                success = False
        except Exception as e:
            print_status(f"Unexpected error deleting key pair {kp_name}: {str(e)}", "ERROR")
            success = False
    
    return success

def delete_internet_gateways(internet_gateways):
    """Delete Internet Gateways"""
    if not internet_gateways:
        print_status("No Internet Gateways found to delete")
        return True
    
    success = True
    for igw in internet_gateways:
        igw_id = igw.id
        try:
            print_status(f"Detaching and deleting Internet Gateway: {igw_id}")
            # Detach from VPC first
            if igw.attachments:
                for attachment in igw.attachments:
                    igw.detach_from_vpc(VpcId=attachment['VpcId'])
                    print_status(f"Detached IGW from VPC: {attachment['VpcId']}")
            
            # Delete the Internet Gateway
            igw.delete()
            print_status(f"Internet Gateway {igw_id} deleted successfully")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidInternetGatewayID.NotFound':
                print_status(f"Internet Gateway {igw_id} already deleted")
            else:
                print_status(f"Error deleting Internet Gateway {igw_id}: {str(e)}", "ERROR")
                success = False
        except Exception as e:
            print_status(f"Unexpected error deleting Internet Gateway {igw_id}: {str(e)}", "ERROR")
            success = False
    
    return success

def delete_subnets(subnets):
    """Delete Subnets"""
    if not subnets:
        print_status("No subnets found to delete")
        return True
    
    success = True
    for subnet in subnets:
        subnet_id = subnet.id
        try:
            print_status(f"Deleting subnet: {subnet_id}")
            subnet.delete()
            print_status(f"Subnet {subnet_id} deleted successfully")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidSubnetID.NotFound':
                print_status(f"Subnet {subnet_id} already deleted")
            else:
                print_status(f"Error deleting subnet {subnet_id}: {str(e)}", "ERROR")
                success = False
        except Exception as e:
            print_status(f"Unexpected error deleting subnet {subnet_id}: {str(e)}", "ERROR")
            success = False
    
    return success

def delete_vpcs(vpcs):
    """Delete VPCs"""
    if not vpcs:
        print_status("No VPCs found to delete")
        return True
    
    success = True
    for vpc in vpcs:
        vpc_id = vpc.id
        try:
            print_status(f"Deleting VPC: {vpc_id}")
            vpc.delete()
            print_status(f"VPC {vpc_id} deleted successfully")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidVpcID.NotFound':
                print_status(f"VPC {vpc_id} already deleted")
            else:
                print_status(f"Error deleting VPC {vpc_id}: {str(e)}", "ERROR")
                success = False
        except Exception as e:
            print_status(f"Unexpected error deleting VPC {vpc_id}: {str(e)}", "ERROR")
            success = False
    
    return success

def delete_local_pem_file():
    """Delete local PEM file"""
    if os.path.exists(KEY_PATH):
        try:
            response = input(f"Delete local PEM file {KEY_PATH}? (y/N): ").strip().lower()
            if response in ['y', 'yes']:
                os.remove(KEY_PATH)
                print_status(f"Local PEM file {KEY_PATH} deleted successfully")
                return True
            else:
                print_status(f"Keeping local PEM file {KEY_PATH}")
                return True
        except Exception as e:
            print_status(f"Error deleting local PEM file: {str(e)}", "ERROR")
            return False
    else:
        print_status(f"Local PEM file {KEY_PATH} not found")
        return True

def main():
    """Main cleanup function"""
    print_status("="*60)
    print_status("AWS LOAD BALANCER CLEANUP SCRIPT", "INFO")
    print_status("="*60)
    print_status(f"Looking for resources with tag: {TAG_KEY}={TAG_VALUE}")
    print_status("This will delete all resources created by create_lb.py")
    
    # Find all resources first
    print_status("Scanning for resources...")
    resources = find_resources_by_tag(TAG_KEY, TAG_VALUE)
    
    # Display found resources
    print_status("="*60)
    print_status("RESOURCES FOUND FOR DELETION", "INFO")
    print_status("="*60)
    print_status(f"Load Balancers: {len(resources['load_balancers'])}")
    print_status(f"Target Groups: {len(resources['target_groups'])}")
    print_status(f"EC2 Instances: {len(resources['instances'])}")
    print_status(f"Security Groups: {len(resources['security_groups'])}")
    print_status(f"VPCs: {len(resources['vpcs'])}")
    print_status(f"Subnets: {len(resources['subnets'])}")
    print_status(f"Internet Gateways: {len(resources['internet_gateways'])}")
    print_status(f"Key Pairs: {len(resources['key_pairs'])}")
    print_status("="*60)
    
    if not any(resources.values()):
        print_status("No resources found to delete")
        return
    
    # Ask for confirmation after showing what will be deleted
    print_status("WARNING: This will permanently delete ALL the resources listed above!")
    response = input("Are you sure you want to proceed with deletion? (y/N): ").strip().lower()
    if response not in ['y', 'yes']:
        print_status("Cleanup cancelled by user")
        return
    
    print_status("Starting resource cleanup...")
    
    # Delete resources in proper order
    cleanup_results = {}
    
    # 1. Delete Listeners first (must be deleted before load balancers)
    print_status("STEP 1: Deleting Load Balancer Listeners")
    cleanup_results['listeners'] = delete_listeners(resources['load_balancers'])
    
    # 2. Delete Load Balancers
    print_status("STEP 2: Deleting Load Balancers")
    cleanup_results['load_balancers'] = delete_load_balancers(resources['load_balancers'])
    
    # 3. Delete Target Groups
    print_status("STEP 3: Deleting Target Groups")
    cleanup_results['target_groups'] = delete_target_groups(resources['target_groups'])
    
    # 4. Terminate EC2 Instances
    print_status("STEP 4: Terminating EC2 Instances")
    cleanup_results['instances'] = delete_ec2_instances(resources['instances'])
    
    # 5. Delete Security Groups
    print_status("STEP 5: Deleting Security Groups")
    cleanup_results['security_groups'] = delete_security_groups(resources['security_groups'])
    
    # 6. Delete Internet Gateways
    print_status("STEP 6: Deleting Internet Gateways")
    cleanup_results['internet_gateways'] = delete_internet_gateways(resources['internet_gateways'])
    
    # 7. Delete Subnets
    print_status("STEP 7: Deleting Subnets")
    cleanup_results['subnets'] = delete_subnets(resources['subnets'])
    
    # 8. Delete VPCs
    print_status("STEP 8: Deleting VPCs")
    cleanup_results['vpcs'] = delete_vpcs(resources['vpcs'])
    
    # 9. Delete Key Pairs
    print_status("STEP 9: Deleting Key Pairs")
    cleanup_results['key_pairs'] = delete_key_pairs(resources['key_pairs'])
    
    # 10. Delete Local PEM file
    print_status("STEP 10: Cleaning up local files")
    cleanup_results['local_files'] = delete_local_pem_file()
    
    # Final summary
    print_status("="*60)
    print_status("CLEANUP SUMMARY", "INFO")
    print_status("="*60)
    
    all_success = True
    for resource_type, success in cleanup_results.items():
        status = "SUCCESS" if success else "FAILED"
        print_status(f"{resource_type.replace('_', ' ').title()}: {status}")
        if not success:
            all_success = False
    
    print_status("="*60)
    if all_success:
        print_status("CLEANUP COMPLETED SUCCESSFULLY", "SUCCESS")
    else:
        print_status("CLEANUP COMPLETED WITH ERRORS", "WARNING")
        print_status("Some resources may still exist. Check AWS console for details.")
    print_status("="*60)

if __name__ == "__main__":
    main()
