#!/usr/bin/env python3
"""
Diagnostic script to troubleshoot load balancer connectivity issues
"""

import boto3
import time
import json
import requests
from botocore.exceptions import ClientError

# Initialize AWS clients
ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')
elbv2 = boto3.client('elbv2')

# Configuration constants
PREFIX = 'coolscale'
TAG_VALUE = 'Coolscale'
LB_NAME = f'{PREFIX}-lb'
LB_SG_NAME = f'{PREFIX}-lb-sg'
INSTANCE_SG_NAME = f'{PREFIX}-instance-sg'
TG_NAME = f'{PREFIX}-tg'

def print_status(message, status="INFO"):
    """Print status messages with timestamps"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{status}] {message}")

def diagnose_security_groups():
    """Check security group configurations"""
    print_status("="*60)
    print_status("DIAGNOSING SECURITY GROUPS", "INFO")
    print_status("="*60)
    
    try:
        # Find VPC
        vpcs = list(ec2.vpcs.filter(Filters=[{'Name': 'tag:Name', 'Values': [f'{PREFIX}-vpc']}]))
        if not vpcs:
            print_status("VPC not found", "ERROR")
            return
        vpc = vpcs[0]
        print_status(f"Found VPC: {vpc.id}")
        
        # Check LB Security Group
        lb_sgs = list(ec2.security_groups.filter(
            Filters=[
                {'Name': 'group-name', 'Values': [LB_SG_NAME]},
                {'Name': 'vpc-id', 'Values': [vpc.id]}
            ]
        ))
        
        if lb_sgs:
            lb_sg = lb_sgs[0]
            print_status(f"LB Security Group: {lb_sg.id}")
            print_status("LB Security Group Ingress Rules:")
            for rule in lb_sg.ip_permissions:
                print_status(f"  Protocol: {rule['IpProtocol']}")
                print_status(f"  From Port: {rule.get('FromPort', 'N/A')}")
                print_status(f"  To Port: {rule.get('ToPort', 'N/A')}")
                for ip_range in rule.get('IpRanges', []):
                    print_status(f"  Source IP: {ip_range.get('CidrIp', 'N/A')}")
                print_status("")
        else:
            print_status("LB Security Group not found", "ERROR")
        
        # Check Instance Security Group
        instance_sgs = list(ec2.security_groups.filter(
            Filters=[
                {'Name': 'group-name', 'Values': [INSTANCE_SG_NAME]},
                {'Name': 'vpc-id', 'Values': [vpc.id]}
            ]
        ))
        
        if instance_sgs:
            instance_sg = instance_sgs[0]
            print_status(f"Instance Security Group: {instance_sg.id}")
            print_status("Instance Security Group Ingress Rules:")
            for rule in instance_sg.ip_permissions:
                print_status(f"  Protocol: {rule['IpProtocol']}")
                print_status(f"  From Port: {rule.get('FromPort', 'N/A')}")
                print_status(f"  To Port: {rule.get('ToPort', 'N/A')}")
                for ip_range in rule.get('IpRanges', []):
                    print_status(f"  Source IP: {ip_range.get('CidrIp', 'N/A')}")
                for sg_pair in rule.get('UserIdGroupPairs', []):
                    print_status(f"  Source Security Group: {sg_pair.get('GroupId', 'N/A')}")
                print_status("")
        else:
            print_status("Instance Security Group not found", "ERROR")
            
    except Exception as e:
        print_status(f"Error diagnosing security groups: {str(e)}", "ERROR")

def diagnose_load_balancer():
    """Check load balancer configuration"""
    print_status("="*60)
    print_status("DIAGNOSING LOAD BALANCER", "INFO")
    print_status("="*60)
    
    try:
        # Get load balancer details
        lb_response = elbv2.describe_load_balancers(Names=[LB_NAME])
        lb = lb_response['LoadBalancers'][0]
        
        print_status(f"Load Balancer: {lb['LoadBalancerName']}")
        print_status(f"DNS Name: {lb['DNSName']}")
        print_status(f"State: {lb['State']['Code']}")
        print_status(f"Type: {lb['Type']}")
        print_status(f"Scheme: {lb['Scheme']}")
        print_status(f"Security Groups: {lb['SecurityGroups']}")
        print_status(f"Subnets: {lb['AvailabilityZones']}")
        
        # Check listeners
        listeners = elbv2.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
        print_status(f"Listeners: {len(listeners['Listeners'])}")
        for listener in listeners['Listeners']:
            print_status(f"  Port: {listener['Port']}, Protocol: {listener['Protocol']}")
            for action in listener.get('DefaultActions', []):
                if action['Type'] == 'forward':
                    print_status(f"  Target Group: {action['TargetGroupArn']}")
        
    except Exception as e:
        print_status(f"Error diagnosing load balancer: {str(e)}", "ERROR")

def diagnose_target_group():
    """Check target group health"""
    print_status("="*60)
    print_status("DIAGNOSING TARGET GROUP", "INFO")
    print_status("="*60)
    
    try:
        # Get target group details
        tg_response = elbv2.describe_target_groups(Names=[TG_NAME])
        tg = tg_response['TargetGroups'][0]
        
        print_status(f"Target Group: {tg['TargetGroupName']}")
        print_status(f"Protocol: {tg['Protocol']}")
        print_status(f"Port: {tg['Port']}")
        print_status(f"Health Check Path: {tg['HealthCheckPath']}")
        print_status(f"Health Check Port: {tg['HealthCheckPort']}")
        
        # Check target health
        health_response = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
        print_status(f"Targets: {len(health_response['TargetHealthDescriptions'])}")
        
        for target in health_response['TargetHealthDescriptions']:
            target_id = target['Target']['Id']
            health_state = target['TargetHealth']['State']
            reason = target['TargetHealth'].get('Reason', 'N/A')
            print_status(f"  Target: {target_id}")
            print_status(f"  Health State: {health_state}")
            print_status(f"  Reason: {reason}")
            
            # Get EC2 instance details
            try:
                instance = ec2.Instance(target_id)
                print_status(f"  Instance State: {instance.state['Name']}")
                print_status(f"  Public IP: {instance.public_ip_address or 'N/A'}")
                print_status(f"  Private IP: {instance.private_ip_address or 'N/A'}")
                print_status(f"  Security Groups: {[sg['GroupId'] for sg in instance.security_groups]}")
            except Exception as e:
                print_status(f"  Error getting instance details: {str(e)}", "ERROR")
            print_status("")
            
    except Exception as e:
        print_status(f"Error diagnosing target group: {str(e)}", "ERROR")

def diagnose_ec2_instances():
    """Check EC2 instances"""
    print_status("="*60)
    print_status("DIAGNOSING EC2 INSTANCES", "INFO")
    print_status("="*60)
    
    try:
        # Find instances with our tags
        instances = list(ec2.instances.filter(
            Filters=[
                {'Name': 'tag:Project', 'Values': [TAG_VALUE]},
                {'Name': 'tag:Name', 'Values': [f'{PREFIX}-instance-1', f'{PREFIX}-instance-2']},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
            ]
        ))
        
        print_status(f"Found {len(instances)} instances")
        
        for i, instance in enumerate(instances, 1):
            print_status(f"Instance {i}:")
            print_status(f"  ID: {instance.id}")
            print_status(f"  State: {instance.state['Name']}")
            print_status(f"  Public IP: {instance.public_ip_address or 'N/A'}")
            print_status(f"  Private IP: {instance.private_ip_address or 'N/A'}")
            print_status(f"  Security Groups: {[sg['GroupId'] for sg in instance.security_groups]}")
            print_status(f"  Subnet: {instance.subnet_id}")
            print_status(f"  AZ: {instance.placement['AvailabilityZone']}")
            
            # Test direct connectivity to instance
            if instance.public_ip_address:
                print_status(f"  Testing direct connectivity to {instance.public_ip_address}...")
                try:
                    response = requests.get(f"http://{instance.public_ip_address}", timeout=10)
                    print_status(f"  Direct HTTP Response: {response.status_code}")
                    if response.status_code == 200:
                        print_status(f"  Response preview: {response.text[:100]}...")
                except Exception as e:
                    print_status(f"  Direct HTTP Error: {str(e)}")
            print_status("")
            
    except Exception as e:
        print_status(f"Error diagnosing EC2 instances: {str(e)}", "ERROR")

def test_connectivity():
    """Test various connectivity scenarios"""
    print_status("="*60)
    print_status("TESTING CONNECTIVITY", "INFO")
    print_status("="*60)
    
    try:
        # Get load balancer DNS name
        lb_response = elbv2.describe_load_balancers(Names=[LB_NAME])
        dns_name = lb_response['LoadBalancers'][0]['DNSName']
        
        print_status(f"Testing connectivity to: {dns_name}")
        
        # Test with different methods
        test_urls = [
            f"http://{dns_name}",
            f"http://{dns_name}/",
            f"https://{dns_name}",
        ]
        
        for url in test_urls:
            print_status(f"Testing: {url}")
            try:
                response = requests.get(url, timeout=10, allow_redirects=False)
                print_status(f"  Status: {response.status_code}")
                print_status(f"  Headers: {dict(response.headers)}")
                print_status(f"  Content: {response.text[:200]}...")
            except requests.exceptions.ConnectionError as e:
                print_status(f"  Connection Error: {str(e)}")
            except requests.exceptions.Timeout as e:
                print_status(f"  Timeout Error: {str(e)}")
            except Exception as e:
                print_status(f"  Other Error: {str(e)}")
            print_status("")
            
    except Exception as e:
        print_status(f"Error testing connectivity: {str(e)}", "ERROR")

def main():
    print_status("Starting load balancer diagnostics...")
    
    diagnose_security_groups()
    diagnose_load_balancer()
    diagnose_target_group()
    diagnose_ec2_instances()
    test_connectivity()
    
    print_status("Diagnostics completed!")

if __name__ == "__main__":
    main()
