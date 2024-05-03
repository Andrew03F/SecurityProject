import tkinter as tk
from tkinter import messagebox
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import threading

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Client")
        
        self.password_label = tk.Label(root, text="Enter password:")
        self.password_label.pack()
        
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()
        
        self.connect_button = tk.Button(root, text="Connect", command=self.connect_to_server)
        self.connect_button.pack()
        
        self.textbox = tk.Text(root, height=10, width=50)
        self.textbox.pack()
        
        self.entry_label = tk.Label(root, text="Enter message:")
        self.entry_label.pack()
        
        self.message_entry = tk.Entry(root)
        self.message_entry.pack()
        
        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack()
        
        self.connected = False
        self.server_conn = None
        self.key = None

    def connect_to_server(self):
        if not self.connected:
            self.connected = True
            password = self.password_entry.get().encode()
            try:
                threading.Thread(target=self.connect_to_server_socket, args=(password,)).start()
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showinfo("Info", "Already connected to server.")

    def connect_to_server_socket(self, password):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect(('127.0.0.1', 8080))
                self.textbox.insert(tk.END, "Connected to server\n")
                salt = client_socket.recv(16)
                self.key = self.derive_key(password, salt)
                self.server_conn = client_socket
                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    iv, ciphertext = data[:16], data[16:]
                    decrypted_data = self.decrypt(ciphertext, self.key, iv)
                    self.textbox.insert(tk.END, f"Received ciphertext: {ciphertext.hex()}\n")
                    self.textbox.insert(tk.END, f"Decrypted message: {decrypted_data.decode()}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_message(self):
        if self.server_conn:
            message = self.message_entry.get()
            encrypted_message_iv, encrypted_message = self.encrypt(message.encode(), self.key)
            self.server_conn.sendall(encrypted_message_iv + encrypted_message)
            self.textbox.insert(tk.END, f"Sent message: {message}\n")
            self.textbox.insert(tk.END, f"Sent ciphertext: {encrypted_message.hex()}\n")
            self.message_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Not connected to server.")

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key (AES-256)
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)

    def decrypt(self, ciphertext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext

    def encrypt(self, plaintext, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ciphertext

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
