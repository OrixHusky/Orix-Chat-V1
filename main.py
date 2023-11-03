import os
import socket
import json
from Crypto.PublicKey import RSA

# File paths
SETTINGS_FILE = "settings.json"
KEYS_DIR = "public_keys"

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_settings(data):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f)

def generate_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

def save_public_key_to_root(public_key):
    with open("public.pem", 'w') as f:
        f.write(public_key)

def load_public_key_from_root():
    if os.path.exists("public.pem"):
        with open("public.pem", 'r') as f:
            return f.read()
    return None

def send_public_key_to_ip(ip):
    public_key_content = load_public_key_from_root()
    if not public_key_content:
        print("No public key found.")
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, 12345))
            s.sendall(b'PUBLIC_KEY:' + public_key_content.encode())
            print(f"Public key sent to {ip}.")
    except Exception as e:
        print(f"Error sending public key to {ip}. Error: {e}")

def save_received_public_key(sender_ip, public_key_content):
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    with open(os.path.join(KEYS_DIR, f"{sender_ip}.pem"), 'w') as f:
        f.write(public_key_content)

def manage_connections(conn, addr):
    with conn:
        print(f"Connected by {addr}")
        data = conn.recv(1024).decode()
        if data.startswith('PUBLIC_KEY:'):
            actual_key = data[len('PUBLIC_KEY:'):].strip()
            save_received_public_key(addr[0], actual_key)
            print(f"Received and saved public key from {addr[0]}.")
        else:
            print(f"Message from {addr[0]}: {data}")

def start_server():
    host = "0.0.0.0"
    port = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("Server listening...")
        while True:
            conn, addr = s.accept()
            manage_connections(conn, addr)

def menu():
    while True:
        print("\nOrix Chat Application")
        print("1. Generate a new key pair.")
        print("2. Display your private key.")
        print("3. Display your public key.")
        print("4. Connect to an IP.")
        print("5. Show active connections.")
        print("6. Change settings.")
        print("7. Send your public key to an IP.")
        print("8. Start the server to listen for messages.")
        print("9. Exit.")
        
        choice = input("Enter your choice: ")

        settings = load_settings()
        
        if choice == "1":
            private_key, public_key = generate_keypair()
            settings["private_key"] = private_key
            save_settings(settings)
            save_public_key_to_root(public_key)
            print("Key pair generated and saved.")
        elif choice == "2":
            print(settings.get("private_key", "No private key found."))
        elif choice == "3":
            public_key_content = load_public_key_from_root()
            if public_key_content:
                print("Your public key is:")
                print(public_key_content)
            else:
                print("No public key found.")
        elif choice == "4":
            target_ip = input("Enter target IP to connect: ")
            # (You'd add logic here to connect and chat with the target IP)
        elif choice == "5":
            # (You'd display any active connections here)
            print("This feature hasn't been implemented yet.")
        elif choice == "6":
            # (You'd implement settings change logic here)
            print("This feature hasn't been implemented yet.")
        elif choice == "7":
            ip_to_send = input("Enter the IP to send your public key to: ")
            send_public_key_to_ip(ip_to_send)
        elif choice == "8":
            start_server()
        elif choice == "9":
            print("Goodbye!")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    menu()
