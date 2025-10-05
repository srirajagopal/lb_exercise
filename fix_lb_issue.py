#!/usr/bin/env python3
"""
Script to fix the load balancer connectivity issue
"""

import boto3
import time
import json

# Initialize AWS clients
ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')

# Configuration constants
PREFIX = 'coolscale'
TAG_VALUE = 'Coolscale'
INSTANCE_SG_NAME = f'{PREFIX}-instance-sg'

def print_status(message, status="INFO"):
    """Print status messages with timestamps"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{status}] {message}")

def fix_instance_security_group():
    """Fix the instance security group to allow HTTP from anywhere for testing"""
    print_status("="*60)
    print_status("FIXING INSTANCE SECURITY GROUP", "INFO")
    print_status("="*60)
    
    try:
        # Find VPC
        vpcs = list(ec2.vpcs.filter(Filters=[{'Name': 'tag:Name', 'Values': [f'{PREFIX}-vpc']}]))
        if not vpcs:
            print_status("VPC not found", "ERROR")
            return
        vpc = vpcs[0]
        
        # Find instance security group
        instance_sgs = list(ec2.security_groups.filter(
            Filters=[
                {'Name': 'group-name', 'Values': [INSTANCE_SG_NAME]},
                {'Name': 'vpc-id', 'Values': [vpc.id]}
            ]
        ))
        
        if not instance_sgs:
            print_status("Instance security group not found", "ERROR")
            return
        
        instance_sg = instance_sgs[0]
        print_status(f"Found instance security group: {instance_sg.id}")
        
        # Check current rules
        print_status("Current ingress rules:")
        for rule in instance_sg.ip_permissions:
            print_status(f"  Protocol: {rule['IpProtocol']}")
            print_status(f"  From Port: {rule.get('FromPort', 'N/A')}")
            print_status(f"  To Port: {rule.get('ToPort', 'N/A')}")
            for ip_range in rule.get('IpRanges', []):
                print_status(f"  Source IP: {ip_range.get('CidrIp', 'N/A')}")
            for sg_pair in rule.get('UserIdGroupPairs', []):
                print_status(f"  Source Security Group: {sg_pair.get('GroupId', 'N/A')}")
            print_status("")
        
        # Check if HTTP from anywhere rule exists
        http_from_anywhere_exists = False
        for rule in instance_sg.ip_permissions:
            if (rule['IpProtocol'] == 'tcp' and 
                rule.get('FromPort') == 80 and 
                rule.get('ToPort') == 80):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        http_from_anywhere_exists = True
                        break
        
        if not http_from_anywhere_exists:
            print_status("Adding HTTP rule to allow access from anywhere (for testing)...")
            instance_sg.authorize_ingress(
                IpPermissions=[
                    {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ]
            )
            print_status("Added HTTP rule from anywhere")
        else:
            print_status("HTTP rule from anywhere already exists")
        
        print_status("Security group fix completed")
        
    except Exception as e:
        print_status(f"Error fixing security group: {str(e)}", "ERROR")

def check_instance_user_data():
    """Check if user data script completed successfully"""
    print_status("="*60)
    print_status("CHECKING INSTANCE USER DATA", "INFO")
    print_status("="*60)
    
    try:
        # Find instances
        instances = list(ec2.instances.filter(
            Filters=[
                {'Name': 'tag:Project', 'Values': [TAG_VALUE]},
                {'Name': 'tag:Name', 'Values': [f'{PREFIX}-instance-1', f'{PREFIX}-instance-2']},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        ))
        
        for i, instance in enumerate(instances, 1):
            print_status(f"Instance {i}: {instance.id}")
            
            # Check if user data is still running
            try:
                response = ec2_client.describe_instance_attribute(
                    InstanceId=instance.id,
                    Attribute='userData'
                )
                if 'UserData' in response and 'Value' in response['UserData']:
                    print_status("  User data script was provided")
                else:
                    print_status("  No user data script found", "WARNING")
            except Exception as e:
                print_status(f"  Error checking user data: {str(e)}")
            
            # Check instance launch time
            launch_time = instance.launch_time
            current_time = time.time()
            launch_time_epoch = launch_time.timestamp()
            running_time = current_time - launch_time_epoch
            
            print_status(f"  Launch time: {launch_time}")
            print_status(f"  Running for: {int(running_time/60)} minutes")
            
            if running_time < 300:  # Less than 5 minutes
                print_status("  Instance is still initializing, user data script may still be running")
            else:
                print_status("  Instance should be fully initialized")
            
            print_status("")
            
    except Exception as e:
        print_status(f"Error checking instance user data: {str(e)}", "ERROR")

def main():
    print_status("Starting load balancer issue fix...")
    
    fix_instance_security_group()
    check_instance_user_data()
    
    print_status("Fix attempt completed!")
    print_status("Please wait a few minutes for the security group changes to take effect")
    print_status("Then try the diagnostic script again: python3 diagnose_lb.py")

if __name__ == "__main__":
    main()
