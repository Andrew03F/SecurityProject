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
    return iv, ciphertext

# Function to decrypt ciphertext using AES
def decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

def main():
    HOST = '127.0.0.1'
    PORT = 8080
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    
    salt = client_socket.recv(16)
    password = input("Enter password for encryption/decryption: ").encode()
    key = derive_key(password, salt)
    
    while True:
        message = input("Enter your message: ")
        if message.lower() == 'quit':
            break
        encrypted_message_iv, encrypted_message = encrypt(message.encode(), key)
        print("Sent ciphertext:", encrypted_message.hex())
        client_socket.sendall(encrypted_message_iv + encrypted_message)
        data = client_socket.recv(1024)
        iv, ciphertext = data[:16], data[16:]
        decrypted_data = decrypt(ciphertext, key, iv)
        print("Received ciphertext:", ciphertext.hex())
        print("Decrypted reply:", decrypted_data.decode())
    
    client_socket.close()

if __name__ == "__main__":
    main()
