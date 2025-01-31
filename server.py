from flask import Flask, render_template, request, jsonify
import socket
import subprocess
import json
import time
import threading
import re

app = Flask(__name__)

# Global variables
clients = {}  # Stores connected clients (IP: Port)
tasks = {}    # Stores tasks and their results
settings = {  # Default settings
    'default_wordlist': '/path/to/wordlist.txt',
    'default_hash_type': 'auto',
    'default_attack_mode': '0',
    'client_timeout': 30  # Timeout in seconds
}

# Server configuration
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5000
CLIENT_PORT = 9999  # Port clients listen on

def scan_network():
    """Scan the network for clients using ARP."""
    try:
        # Run arp-scan to discover devices on the network
        result = subprocess.run(['arp-scan', '--localnet'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Error running arp-scan. Ensure it is installed.")
            return []

        # Parse the output to extract IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, result.stdout)

        # Filter out the server's own IP and known non-client devices
        server_ip = socket.gethostbyname(socket.gethostname())
        ips = [ip for ip in ips if ip != server_ip and ip not in clients]

        return ips
    except Exception as e:
        print(f"Error during network scan: {e}")
        return []

def auto_add_clients():
    """Automatically add detected clients."""
    ips = scan_network()
    for ip in ips:
        if ip not in clients:
            clients[ip] = {'status': 'Connected'}
            print(f"Auto-added client: {ip}")

# Periodically scan the network (e.g., every 60 seconds)
def start_auto_scan():
    while True:
        auto_add_clients()
        time.sleep(60)  # Scan every 60 seconds

# Start the auto-scan thread
threading.Thread(target=start_auto_scan, daemon=True).start()

@app.route('/')
def index():
    return render_template('index.html', clients=clients, tasks=tasks, settings=settings)

@app.route('/crack', methods=['POST'])
def crack():
    try:
        hash_value = request.form['hash']
        hash_type = request.form.get('hash_type', settings['default_hash_type'])
        attack_mode = request.form.get('attack_mode', settings['default_attack_mode'])
        wordlist = request.form.get('wordlist', settings['default_wordlist'])

        if not hash_value:
            return jsonify({"error": "Hash value is required."}), 400

        if hash_type == 'auto':
            # Use hashid to identify the hash type
            try:
                hash_id = subprocess.getoutput(f'hashid {hash_value}')
                hash_type = hash_id.splitlines()[1].split()[0]
            except Exception as e:
                return jsonify({"error": f"Failed to identify hash type: {e}"}), 400

        # Create a task
        task_id = len(tasks) + 1
        tasks[task_id] = {
            'hash': hash_value,
            'hash_type': hash_type,
            'attack_mode': attack_mode,
            'wordlist': wordlist,
            'status': 'Pending',
            'result': None
        }

        # Distribute the task to clients
        for client_ip in clients:
            if not send_task_to_client(client_ip, task_id):
                tasks[task_id]['status'] = 'Failed'
                return jsonify({"error": f"Failed to send task to client {client_ip}."}), 500

        return jsonify({"message": "Cracking process started on all clients.", "task_id": task_id})
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500

def send_task_to_client(client_ip, task_id):
    task = tasks[task_id]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(settings['client_timeout'])
            s.connect((client_ip, CLIENT_PORT))
            s.send(json.dumps({
                'task_id': task_id,
                'hash': task['hash'],
                'hash_type': task['hash_type'],
                'attack_mode': task['attack_mode'],
                'wordlist': task['wordlist']
            }).encode())
            return True
    except Exception as e:
        print(f"Failed to send task to {client_ip}: {e}")
        return False

@app.route('/add_client', methods=['POST'])
def add_client():
    try:
        client_ip = request.form['client_ip']
        if not client_ip:
            return jsonify({"error": "Client IP is required."}), 400
        clients[client_ip] = {'status': 'Connected'}
        return jsonify({"message": f"Client {client_ip} added successfully."})
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500

@app.route('/remove_client', methods=['POST'])
def remove_client():
    try:
        client_ip = request.form['client_ip']
        if client_ip in clients:
            del clients[client_ip]
            return jsonify({"message": f"Client {client_ip} removed successfully."})
        return jsonify({"error": f"Client {client_ip} not found."}), 404
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500

@app.route('/update_settings', methods=['POST'])
def update_settings():
    try:
        settings['default_wordlist'] = request.form.get('default_wordlist', settings['default_wordlist'])
        settings['default_hash_type'] = request.form.get('default_hash_type', settings['default_hash_type'])
        settings['default_attack_mode'] = request.form.get('default_attack_mode', settings['default_attack_mode'])
        settings['client_timeout'] = int(request.form.get('client_timeout', settings['client_timeout']))
        return jsonify({"message": "Settings updated successfully.", "settings": settings})
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500

@app.route('/scan_network', methods=['GET'])
def handle_scan_network():
    try:
        auto_add_clients()
        return jsonify({"message": "Network scan completed.", "clients": clients})
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500

if __name__ == '__main__':
    app.run(host=SERVER_HOST, port=SERVER_PORT)