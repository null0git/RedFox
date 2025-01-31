import socket
import subprocess
import json

CLIENT_PORT = 9999  # Port to listen on
SERVER_IP = '192.168.1.10'  # Server IP
SERVER_PORT = 5000  # Server port

def crack_password(hash_value, hash_type, attack_mode, wordlist):
    try:
        if attack_mode == '0':
            # Dictionary attack
            command = f'hashcat -m {hash_type} -a 0 {hash_value} {wordlist}'
        elif attack_mode == '1':
            # Brute force attack
            command = f'hashcat -m {hash_type} -a 3 {hash_value}'
        else:
            return "Unsupported attack mode"

        result = subprocess.getoutput(command)
        return result
    except Exception as e:
        return f"Error during cracking: {e}"

def send_result_to_server(task_id, result):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_IP, SERVER_PORT))
            s.send(json.dumps({
                'task_id': task_id,
                'result': result
            }).encode())
    except Exception as e:
        print(f"Failed to send result to server: {e}")

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', CLIENT_PORT))
        s.listen()
        print(f"Client listening on port {CLIENT_PORT}...")

        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024).decode()
                if data:
                    task = json.loads(data)
                    print(f"Received task: {task}")

                    # Perform cracking
                    result = crack_password(task['hash'], task['hash_type'], task['attack_mode'], task['wordlist'])

                    # Send result back to server
                    send_result_to_server(task['task_id'], result)

if __name__ == '__main__':
    start_client()