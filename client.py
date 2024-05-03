import socket

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Replace 'server_ip' with the IP address of the server
server_ip = '127.0.0.1'  # Example IP

port = 12345  # Port to connect to

# Connect to the server
client_socket.connect((server_ip, port))

# Receive data from the server
data = client_socket.recv(1024)

print(f"Received from server: {data.decode()}")

# Close the connection with the server
client_socket.close()
