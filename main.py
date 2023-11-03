import os
import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
 
# Constants and Global Variables
BUFFER_SIZE = 4096
ACK_RECEIVED = b'ACK_RECEIVED'
ACK_TIMEOUT = 5.0
KEYS_DIRECTORY = "keys"
SETTINGS_FILE = "settings.txt"
connections = []

# Function Definitions

def generate_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f)

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_key_to_directory(ip, key_type, key_content):
    if not os.path.exists(KEYS_DIRECTORY):
        os.mkdir(KEYS_DIRECTORY)
    
    ip_directory = os.path.join(KEYS_DIRECTORY, ip.replace(".", "_"))
    if not os.path.exists(ip_directory):
        os.mkdir(ip_directory)
    
    key_file = os.path.join(ip_directory, key_type + ".pem")
    with open(key_file, 'w') as f:
        f.write(key_content)

def load_key_from_directory(ip, key_type):
    ip_directory = os.path.join(KEYS_DIRECTORY, ip.replace(".", "_"))
    key_file = os.path.join(ip_directory, key_type + ".pem")
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            return f.read()
    return None

def handle_client(client_socket, client_ip, settings):
    while True:
        try:
            encrypted_msg = client_socket.recv(BUFFER_SIZE)
            if not encrypted_msg:
                print(f"{client_ip} has disconnected.")
                connections.remove(client_socket)
                client_socket.close()
                break

            if encrypted_msg == ACK_RECEIVED:
                print(f"Received acknowledgment from {client_ip}")
                continue

            private_key = RSA.import_key(settings["private_key"].encode())
            cipher = PKCS1_OAEP.new(private_key)
            decrypted_msg = cipher.decrypt(encrypted_msg)
            print(f"Received encrypted message from {client_ip}: {decrypted_msg.decode()}")
            client_socket.send(ACK_RECEIVED)

        except Exception as e:
            print(f"Error in client handler for {client_ip}. Error: {e}")
            connections.remove(client_socket)
            client_socket.close()
            break

# Main Logic

settings = load_settings()

while True:
    print("   ____       _          _____ _           _   ")
    print("  / __ \     (_)        / ____| |         | | ")
    print(" | |  | |_ __ ___  __  | |    | |__   __ _| |_ ")
    print(" | |  | | '__| \ \/ /  | |    | '_ \ / _` | __|")
    print(" | |__| | |  | |>  <   | |____| | | | (_| | |_ ")
    print("  \____/|_|  |_/_/\_\   \_____|_| |_|\__,_|\__|")
    print("\nMenu:")
    print("1. Generate and save new key pair.")
    print("2. Save a known peer's public key.")
    print("3. Connect to a peer.")
    print("4. Send an encrypted message.")
    print("5. Exit.")
    
    choice = input("Enter your choice: ")

    if choice == "1":
        private_key, public_key = generate_keypair()
        settings["private_key"] = private_key
        settings["public_key"] = public_key
        save_settings(settings)
        print("Key pair generated and saved.")

    elif choice == "2":
        ip = input("Enter the IP of the peer: ")
        public_key = input("Paste the public key of the peer: ")
        save_key_to_directory(ip, "public", public_key)
        print(f"Saved public key for {ip}.")

    elif choice == "3":
        ip = input("Enter the IP to connect to: ")
        port = int(input("Enter the port to connect to (default 65432): ") or 65432)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        connections.append(s)
        print(f"Connected to {ip} on port {port}.")

    elif choice == "4":
        ip_to_send = input("Enter the IP to send an encrypted message to: ")
        message = input("Enter the message: ")
        peer_public_key_content = load_key_from_directory(ip_to_send, "public")
        if peer_public_key_content:
            peer_public_key = RSA.import_key(peer_public_key_content)
            cipher = PKCS1_OAEP.new(peer_public_key)
            encrypted_message = cipher.encrypt(message.encode())
            for conn in connections:
                if conn.getpeername()[0] == ip_to_send:
                    conn.send(encrypted_message)
                    try:
                        acknowledgment = conn.recv(BUFFER_SIZE)
                        if acknowledgment == ACK_RECEIVED:
                            print("Message successfully received by the peer.")
                        else:
                            print("Error in acknowledgment from the peer.")
                    except socket.timeout:
                        print("Timed out waiting for acknowledgment. Message might not have been received.")
                    break
        else:
            print(f"No public key found for {ip_to_send}.")

    elif choice == "5":
        for conn in connections:
            conn.close()
        break
