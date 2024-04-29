# server.py

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

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()
    return message

def receive_message(connection, buffer_size=1024):
    return connection.recv(buffer_size)

def send_message(connection, message):
    connection.sendall(message)

def main():
    password = b"supersecret"
    salt = b"somesalt"
    key = derive_key(password, salt)

    # Listen on all network interfaces
    server_address = ('', 12345)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(1)

    print("Waiting for connection...")
    connection, client_address = server_socket.accept()
    print("Connection established with:", client_address)

    try:
        while True:
            ciphertext = receive_message(connection)
            plaintext = decrypt_message(key, ciphertext)
            print("Received:", plaintext.decode())

            # Echo back to the client
            send_message(connection, ciphertext)

    finally:
        connection.close()
        server_socket.close()

if __name__ == "__main__":
    main()
