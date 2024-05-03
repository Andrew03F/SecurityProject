import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

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

def main():
    HOST = '10.204.167.105'
    PORT = 8080
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print("Server listening on port", PORT)
    conn, addr = server_socket.accept()
    print('Connected to', addr)
    
    salt = os.urandom(16)
    conn.sendall(salt)  # Send salt to client
    
    password = input("Enter password for encryption/decryption: ").encode()
    key = derive_key(password, salt)
    
    while True:
        data = conn.recv(1024)
        if not data:
            break
        decrypted_data = decrypt(data, key)
        print("Received message:", decrypted_data.decode())
        reply = input("Enter your reply: ")
        encrypted_reply = encrypt(reply.encode(), key)
        conn.sendall(encrypted_reply)
    
    conn.close()

if __name__ == "__main__":
    main()
