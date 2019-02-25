import socket
import struct

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverIP = "127.0.0.1"
port = 2000
serverSocket.bind((serverIP, port))
serverSocket.listen(1)
connection = None
print("Ready to receive")


def handle_client_message(msg):  # Handles the different number of cases
    b = False  # boolean when no matches are found
    if msg == "end":
        msg = 'Ending Connection'
        b = True
    if msg == 'ben@gmail.com':
        msg = 'Ben Kenobi'
        b = True
    if msg == 'luke@gmail.com':
        msg = 'Luke Skywalker'
        b = True
    if msg == 'leia@gmail.com':
        msg = 'Leia Organa'
        b = True
    if msg == 'anakin@gmail.com':
        msg = 'Anakin Skywalker'
        b = True
    if not b:
        msg = "No matches found"
    return msg


while True:
    print("Waiting for connection...")

    connection, address = serverSocket.accept()
    try:
        run = True
        while run:  # run boolean when user wants to end connection
            message = connection.recv(257)  # Size of 257, 1 for message type and length, 255 for message
            if len(message.decode()) != 0:
                length = message[1]  # Get character length of the message
                message = struct.unpack('cB{}s'.format(length), message)  # Using length to unpack the struct
                print("Client Message Received")
                print("Client Message Type:", message[0].decode())
                print("Client Message Length:", length)
                print("Client Message:", message[2].decode())
                message = handle_client_message(message[2].decode())  # Returns the appropriate response to client input

                print("Message Type: ", "R")  # Server messages should always be the response type
                print("Message Length:", len(message))
                print("Message:", message)

                if message == 'Ending Connection':
                    run = False

                message = struct.pack('cB{}s'.format(len(message)), "R".encode(), len(message), message.encode())
                connection.send(message)

                print("Message Sent to Client")
                if not run:  # Ends connection to client and stops loop
                    connection.close()
                print("\n")
    finally:
        connection.close()
