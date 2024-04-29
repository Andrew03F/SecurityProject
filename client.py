# client.py

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_message(key, message):
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()
    return message

def send_message(sock, message):
    sock.sendall(message)

def receive_message(sock, buffer_size=1024):
    return sock.recv(buffer_size)

def main():
    password = b"supersecret"
    salt = b"somesalt"
    key = derive_key(password, salt)

    # Prompt user for server IP address or hostname
    server_address = input("Enter server IP address or hostname: ")
    server_port = 10000  # Set the port number

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect((server_address, server_port))

        while True:
            plaintext = input("Enter message: ")
            encrypted_message = encrypt_message(key, plaintext.encode())
            send_message(client_socket, encrypted_message)

            ciphertext = receive_message(client_socket)
            decrypted_message = decrypt_message(key, ciphertext)
            print("Received:", decrypted_message.decode())

    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
