import os
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import threading

# Constants
KEY_HEADER = b'SENDING_PUBLIC_KEY'
RELAY_SERVER_IP = '172.126.229.186'  # This should be your relay server's IP.
RELAY_SERVER_PORT = 4465      # And its port.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def generate_keys():
    # Key generation
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save keys
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)
    print("Keys generated and saved.")

def encrypt_message(message, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message

def decrypt_message(encrypted_message):
    with open("private_key.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
    return decrypted_message

def send_message(target_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((RELAY_SERVER_IP, RELAY_SERVER_PORT))
    except Exception as e:
        print(f"Failed to connect to the relay server: {e}")
        return

    choice = input("Send encrypted message (E) or unencrypted (U) or public key (K): ").lower()
    
    # Prepending the target IP to the message/payload for the relay server.
    payload = target_ip.encode() + b':' 

    if choice == "k":
        with open("public.pem", "rb") as f:
            key_data = f.read()
        s.send(payload + KEY_HEADER + key_data)
        print("Public key sent to relay server.")
    elif choice == "e":
        target_key_file = f'public_keys/{target_ip}.pem'
        if not os.path.exists(target_key_file):
            print(f"No public key found for {target_ip}. Cannot send encrypted message.")
            return
        with open(target_key_file, "rb") as f:
            target_pub_key = RSA.import_key(f.read())
        message = input("Enter your encrypted message: ").encode('utf-8')
        encrypted_message = encrypt_message(message, target_pub_key)
        s.send(payload + encrypted_message)
        print("Encrypted message sent to relay server.")
    elif choice == "u":
        message = input("Enter your unencrypted message: ").encode('utf-8')
        s.send(payload + message)
        print("Unencrypted message sent to relay server.")
    else:
        print("Invalid choice.")
    s.close()


def process_received_data(data):
    # Check if the data starts with the KEY_HEADER
    if data.startswith(KEY_HEADER):
        # Remove the KEY_HEADER prefix to get the actual key data
        key_data = data[len(KEY_HEADER):]
        # Assuming the relay server sends the sender's IP before the KEY_HEADER (if it doesn't, you'll need to change this part)
        try:
            sender_ip, key_data_actual = key_data.split(b'\n', 1)  # Trying to extract sender IP from the data
            with open(f"public_keys/{sender_ip.decode()}.pem", "wb") as f:
                f.write(key_data_actual)  # write the actual key data (after the sender IP) to file
            print(f"Received and saved public key from {sender_ip.decode()}")
        except ValueError:
            print("Received public key in an unexpected format:", key_data)
            return

    else:
        try:
            sender_ip, message = data.split(b':', 1)
            try:
                decrypted_message = decrypt_message(message)
                with open(f"messages/{sender_ip.decode()}.txt", "a") as f:
                    f.write(f"{sender_ip.decode()}: {decrypted_message}\n")
                print(f"Received encrypted message from {sender_ip.decode()} and saved.")
            except:
                with open(f"messages/{sender_ip.decode()}.txt", "a") as f:
                    f.write(f"{sender_ip.decode()}: {message.decode('utf-8')}\n")
                print(f"Received unencrypted message from {sender_ip.decode()} and saved.")
        except ValueError:
            print("Received data in an unexpected format:", data)
            return

def listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((RELAY_SERVER_IP, RELAY_SERVER_PORT))
    
    while True:
        data = s.recv(2048)
        if data == b"That client is not online":
            print(data.decode())
        else:
            process_received_data(data)

def view_received_messages_menu():
    ips = os.listdir("messages")
    while True:
        print("\nReceived Messages Menu:")
        for index, ip in enumerate(ips, start=1):
            print(f"{index}. {ip.replace('.txt', '')}")
        print(f"{len(ips) + 1}. Go back")
        choice = input("> ")

        if choice.isdigit() and 1 <= int(choice) <= len(ips):
            ip = ips[int(choice) - 1]
            with open(f"messages/{ip}", "r") as f:
                print(f"\nMessages from {ip.replace('.txt', '')}:")
                print(f.read())
                input("Press any key to continue...")
        elif choice == str(len(ips) + 1):
            break
        else:
            print("Invalid choice.")

def menu():
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print("   ____       _          _____ _           _   ")
        print("  / __ \     (_)        / ____| |         | | ")
        print(" | |  | |_ __ ___  __  | |    | |__   __ _| |_ ")
        print(" | |  | | '__| \ \/ /  | |    | '_ \ / _` | __|")
        print(" | |__| | |  | |>  <   | |____| | | | (_| | |_ ")
        print("  \____/|_|  |_/_/\_\   \_____|_| |_|\__,_|\__|")
        print("\nMENU")
        print("1. Generate Public/Private Key Pair")
        print("2. Send Message")
        print("3. View Received Messages")
        print("4. Send My Public Key")
        print("5. Exit")
        choice = input("> ")

        if choice == "1":
            generate_keys()
        elif choice == "2":
            ip = input("Enter the target IP address: ")
            send_message(ip)
        elif choice == "3":
            view_received_messages_menu()
        elif choice == "4":
            ip = input("Enter the target IP address to send your public key: ")
            send_message(ip)
        elif choice == "5":
            s.close()
            break

if __name__ == '__main__':
    if not os.path.exists("public_keys"):
        os.makedirs("public_keys")
    if not os.path.exists("messages"):
        os.makedirs("messages")
    
    listener_thread = threading.Thread(target=listener)
    listener_thread.daemon = True
    listener_thread.start()

    menu()
