import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import threading
import tkinter as tk
from tkinter import scrolledtext

# Function to derive key from password using PBKDF2
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key (AES-256)
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# Function to encrypt data using AES
def encrypt(plaintext, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# Function to decrypt ciphertext using AES
def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

# Function to handle incoming messages
def handle_messages():
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        decrypted_data = decrypt(data, key)
        chat_box.insert(tk.END, f"Received: {decrypted_data.decode()}\n")

# Function to start the client
def start_client():
    global client_socket, key
    HOST = '127.0.0.1'
    PORT = 8080
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    
    salt = client_socket.recv(16)
    password = password_entry.get().encode()
    key = derive_key(password, salt)

    threading.Thread(target=handle_messages, daemon=True).start()

# Function to send a message
def send_message():
    message = message_entry.get()
    encrypted_message = encrypt(message.encode(), key)
    client_socket.sendall(encrypted_message)
    chat_box.insert(tk.END, f"Sent: {message}\n")
    message_entry.delete(0, tk.END)

# Create GUI
root = tk.Tk()
root.title("Client")
root.geometry("400x300")

chat_label = tk.Label(root, text="Chat:")
chat_label.pack()

chat_box = scrolledtext.ScrolledText(root, width=40, height=10)
chat_box.pack()

password_label = tk.Label(root, text="Enter password:")
password_label.pack()

password_entry = tk.Entry(root, show="*")
password_entry.pack()

start_button = tk.Button(root, text="Start Client", command=start_client)
start_button.pack()

message_label = tk.Label(root, text="Enter message:")
message_label.pack()

message_entry = tk.Entry(root)
message_entry.pack()

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack()

root.mainloop()
