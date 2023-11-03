import os
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import threading

# Constants
KEY_HEADER = b'SENDING_PUBLIC_KEY'

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
    s.connect((target_ip, 12345))

    choice = input("Send encrypted message (E) or unencrypted (U) or public key (K): ").lower()
    
    if choice == "k":
        # Sending public key
        with open("public.pem", "rb") as f:
            key_data = f.read()
        s.send(KEY_HEADER + key_data)
        print("Public key sent.")
    elif choice == "e":
        target_key_file = f'public_keys/{target_ip}.pem'
        if not os.path.exists(target_key_file):
            print(f"No public key found for {target_ip}. Cannot send encrypted message.")
            return
        with open(target_key_file, "rb") as f:
            target_pub_key = RSA.import_key(f.read())
        message = input("Enter your encrypted message: ").encode('utf-8')
        encrypted_message = encrypt_message(message, target_pub_key)
        s.send(encrypted_message)
        print("Encrypted message sent.")
    elif choice == "u":
        message = input("Enter your unencrypted message: ").encode('utf-8')
        s.send(message)
        print("Unencrypted message sent.")
    else:
        print("Invalid choice.")
    s.close()

def manage_connections(conn, addr):
    data = conn.recv(2048)
    if data.startswith(KEY_HEADER):
        key_data = data[len(KEY_HEADER):]
        with open(f"public_keys/{addr[0]}.pem", "wb") as f:
            f.write(key_data)
        print(f"Received and saved public key from {addr[0]}")
    else:
        try:
            decrypted_message = decrypt_message(data)
            with open(f"messages/{addr[0]}.txt", "a") as f:
                f.write(f"{addr[0]}: {decrypted_message}\n")
            print(f"Received encrypted message from {addr[0]} and saved.")
        except:
            with open(f"messages/{addr[0]}.txt", "a") as f:
                f.write(f"{addr[0]}: {data.decode('utf-8')}\n")
            print(f"Received unencrypted message from {addr[0]} and saved.")

def listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 12345))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        manage_connections(conn, addr)

def view_received_messages():
    ips = os.listdir("messages")
    for ip in ips:
        print(f"\nMessages from {ip.replace('.txt', '')}:")
        with open(f"messages/{ip}", "r") as f:
            print(f.read())

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
            view_received_messages()
        elif choice == "4":
            ip = input("Enter the target IP address to send your public key: ")
            send_message(ip)
        elif choice == "5":
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
