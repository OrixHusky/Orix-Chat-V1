import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json

SETTINGS_FILE = "settings.json"
KEYS_DIR = "keys"
MSG_DIR = "messages"

if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)
if not os.path.exists(MSG_DIR):
    os.makedirs(MSG_DIR)


def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {}
    with open(SETTINGS_FILE, 'r') as f:
        return json.load(f)


def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=4)


def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def save_received_public_key(ip, public_key):
    with open(os.path.join(KEYS_DIR, f"{ip}.pem"), 'w') as f:
        f.write(public_key)


def save_received_message(ip, message):
    with open(os.path.join(MSG_DIR, f"{ip}.txt"), 'a') as f:
        f.write(message + '\n')


def encrypt_message(public_key_content, message):
    recipient_key = RSA.import_key(public_key_content)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_data = cipher_rsa.encrypt(message.encode())
    return enc_data


def send_message_to_ip(target_ip, message):
    public_key_file = os.path.join(KEYS_DIR, f"{target_ip}.pem")

    if os.path.exists(public_key_file):
        with open(public_key_file, 'r') as f:
            recipient_public_key = f.read()
            encrypted_message = encrypt_message(recipient_public_key, message)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((target_ip, 12345))
                    s.sendall(encrypted_message)
                    print(f"Encrypted message sent to {target_ip}.")
            except Exception as e:
                print(f"Error sending encrypted message to {target_ip}. Error: {e}")
    else:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, 12345))
                s.sendall(message.encode())
                print(f"Unencrypted message sent to {target_ip}.")
        except Exception as e:
            print(f"Error sending unencrypted message to {target_ip}. Error: {e}")


def manage_connections(conn, addr):
    settings = load_settings()
    private_key_content = settings.get("private_key")

    with conn:
        data = conn.recv(1024)
        if data.startswith(b'PUBLIC_KEY:'):
            actual_key = data[len(b'PUBLIC_KEY:'):].strip().decode()
            save_received_public_key(addr[0], actual_key)
            print(f"Received and saved public key from {addr[0]}.")
        elif private_key_content:
            try:
                private_key = RSA.import_key(private_key_content)
                cipher_rsa = PKCS1_OAEP.new(private_key)
                decrypted_message = cipher_rsa.decrypt(data).decode()
                print(f"Encrypted message from {addr[0]}: {decrypted_message}")
                save_received_message(addr[0], decrypted_message)
            except ValueError:
                print(f"Message from {addr[0]}: {data.decode()}")
                save_received_message(addr[0], data.decode())
        else:
            print(f"Message from {addr[0]}: {data.decode()}")
            save_received_message(addr[0], data.decode())


def menu():
    while True:
        print("   ____       _          _____ _           _   ")
        print("  / __ \     (_)        / ____| |         | | ")
        print(" | |  | |_ __ ___  __  | |    | |__   __ _| |_ ")
        print(" | |  | | '__| \ \/ /  | |    | '_ \ / _` | __|")
        print(" | |__| | |  | |>  <   | |____| | | | (_| | |_ ")
        print("  \____/|_|  |_/_/\_\   \_____|_| |_|\__,_|\__|")
        print("\n1. Generate new public/private key pair")
        print("2. Configure settings")
        print("3. Send message to IP")
        print("4. View Received Messages")
        print("5. Send my public key to an IP")
        print("6. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            private_key, public_key = generate_key_pair()
            settings = load_settings()
            settings['private_key'] = private_key.decode()
            save_settings(settings)
            with open("my_public_key.pem", 'w') as f:
                f.write(public_key.decode())
            print("Key pair generated. Public key saved as 'my_public_key.pem'")
        elif choice == "2":
            settings = load_settings()
            print("\nConfigurations:")
            for key, value in settings.items():
                print(f"{key}: {value}")
            key = input("\nEnter key to modify or add: ")
            value = input(f"Enter value for {key}: ")
            settings[key] = value
            save_settings(settings)
            print("Settings saved.")
        elif choice == "3":
            target_ip = input("Enter target IP to connect: ")
            message = input("Enter your message: ")
            send_message_to_ip(target_ip, message)
        elif choice == "4":
            for filename in os.listdir(MSG_DIR):
                ip = filename.replace('.txt', '')
                with open(os.path.join(MSG_DIR, filename), 'r') as f:
                    messages = f.readlines()
                    print(f"\nMessages from {ip}:")
                    for message in messages:
                        print(message.strip())
        elif choice == "5":
            target_ip = input("Enter target IP to send your public key: ")
            with open("my_public_key.pem", 'r') as f:
                public_key_content = f.read()
                message = f"PUBLIC_KEY:{public_key_content}"
                send_message_to_ip(target_ip, message)
        elif choice == "6":
            break


if __name__ == '__main__':
    # Always listening for incoming messages
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 12345))
    s.listen(5)
    print("Started listening for incoming connections...")

    while True:
        conn, addr = s.accept()
        manage_connections(conn, addr)

    menu()
