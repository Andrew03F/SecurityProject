import socket

# Define the server's IP and port
SERVER_IP = "127.0.0.1"  # Replace with the actual IP address
SERVER_PORT = 12345

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((SERVER_IP, SERVER_PORT))

while True:
    # Get user input
    message = input("Enter a message to send to the server (type 'exit' to quit): ")

    if message.lower() == "exit":
        break  # Exit the loop if user types 'exit'

    # Send the message to the server
    client_socket.send(message.encode())

    # Receive the server's response
    response = client_socket.recv(1024).decode()
    print("Received from server:", response)

    # Get user input for sending a message back to the server
    message = input("Enter a message to send to the server (type 'exit' to quit): ")

    if message.lower() == "exit":
        break  # Exit the loop if user types 'exit'

    # Send the message to the server
    client_socket.send(message.encode())

# Close the connection
client_socket.close()
