#!/usr/bin/env python3
"""
Script to manually set up Flask on EC2 instances
"""

import boto3
import time
import paramiko
import os

# Initialize AWS clients
ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')

# Configuration constants
PREFIX = 'coolscale'
TAG_VALUE = 'Coolscale'
KEY_NAME = f'{PREFIX}-key'
key_path = f'./{KEY_NAME}.pem'

def print_status(message, status="INFO"):
    """Print status messages with timestamps"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{status}] {message}")

def get_ssh_connection(public_ip):
    """Create SSH connection to instance"""
    try:
        # Set correct permissions for key file
        os.chmod(key_path, 0o400)
        
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to instance
        ssh.connect(
            hostname=public_ip,
            username='ec2-user',
            key_filename=key_path,
            timeout=30
        )
        
        return ssh
    except Exception as e:
        print_status(f"Failed to connect to {public_ip}: {str(e)}", "ERROR")
        return None

def install_flask_on_instance(public_ip):
    """Install and start Flask on an instance"""
    print_status(f"Installing Flask on {public_ip}...")
    
    ssh = get_ssh_connection(public_ip)
    if not ssh:
        return False
    
    try:
        # Commands to install and start Flask
        commands = [
            # Update system
            "sudo yum update -y",
            
            # Install Python3 and pip
            "sudo yum install -y python3 python3-pip",
            
            # Install Flask
            "pip3 install flask requests --user",
            
            # Create Flask application directory
            "mkdir -p ~/flaskapp",
            "cd ~/flaskapp",
            
            # Create Flask application
            '''cat > app.py << 'EOF'
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
EOF''',
            
            # Make the script executable
            "chmod +x app.py",
            
            # Kill any existing Flask processes
            "sudo pkill -f flask || true",
            "sudo pkill -f app.py || true",
            
            # Start Flask application as root on port 80
            "sudo /usr/bin/python3 app.py > /tmp/flask.log 2>&1 &"
        ]
        
        # Execute commands
        for i, command in enumerate(commands, 1):
            print_status(f"Executing command {i}/{len(commands)}: {command[:50]}...")
            
            stdin, stdout, stderr = ssh.exec_command(command)
            
            # Wait for command to complete
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error_output = stderr.read().decode()
                print_status(f"Command failed with exit status {exit_status}: {error_output}", "WARNING")
            else:
                print_status(f"Command {i} completed successfully")
        
        # Check if Flask is running
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep -v grep | grep python3")
        processes = stdout.read().decode()
        
        if "app.py" in processes:
            print_status("Flask application is running")
        else:
            print_status("Flask application may not be running", "WARNING")
            # Check logs
            stdin, stdout, stderr = ssh.exec_command("cat /tmp/flask.log")
            logs = stdout.read().decode()
            print_status(f"Flask logs: {logs}")
        
        # Test local connectivity
        stdin, stdout, stderr = ssh.exec_command("curl -s http://localhost/ | head -100")
        response = stdout.read().decode()
        
        if response:
            print_status(f"Local Flask test successful: {response[:100]}...")
        else:
            print_status("Local Flask test failed", "WARNING")
        
        ssh.close()
        return True
        
    except Exception as e:
        print_status(f"Error installing Flask: {str(e)}", "ERROR")
        ssh.close()
        return False

def main():
    print_status("Starting manual Flask setup...")
    
    try:
        # Find instances
        instances = list(ec2.instances.filter(
            Filters=[
                {'Name': 'tag:Project', 'Values': [TAG_VALUE]},
                {'Name': 'tag:Name', 'Values': [f'{PREFIX}-instance-1', f'{PREFIX}-instance-2']},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        ))
        
        if not instances:
            print_status("No running instances found", "ERROR")
            return
        
        for i, instance in enumerate(instances, 1):
            if instance.public_ip_address:
                print_status(f"Setting up Flask on instance {i}: {instance.id}")
                success = install_flask_on_instance(instance.public_ip_address)
                if success:
                    print_status(f"Flask setup completed for instance {i}")
                else:
                    print_status(f"Flask setup failed for instance {i}", "ERROR")
                print_status("")
            else:
                print_status(f"Instance {i} has no public IP address", "ERROR")
        
        print_status("Manual Flask setup completed!")
        print_status("Please wait a moment and test connectivity again")
        
    except Exception as e:
        print_status(f"Error in main: {str(e)}", "ERROR")

if __name__ == "__main__":
    main()
