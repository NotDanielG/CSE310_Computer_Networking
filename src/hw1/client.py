import socket
import struct

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverIP = "127.0.0.1"
serverPort = 2000
clientSocket.connect((serverIP, serverPort))

run = True
while run:  # Will end once user puts in 'end' in the input
    sentence = input('Please type your message:')  # Asking user for the input

    length = len(sentence)
    print("Message Type: Q")  # Message sent to server from client should always be a query
    print("Message Length:", length)
    print("Message:", sentence)

    while length > 255:  # Loops constantly until user inputs in a valid size
        sentence = input('Input is too long. Type another message:')
        length = len(sentence)
        print("Message Type: Q")
        print("Message Length:", length)
        print("Message:", sentence)

    message = struct.pack("cB{}s".format(len(sentence)), "Q".encode(), len(sentence), sentence.encode())
    print("Message sent to server.")
    clientSocket.send(message)

    message = clientSocket.recv(257)  # Receives input from server
    length = message[1]
    message = struct.unpack('cB{}s'.format(length), message)
    if message[2].decode() == "Ending Connection":  # Stops client connection to server
        clientSocket.close()
        run = False
    print("Server Message Type:", message[0].decode())
    print("Server Message Length:", length)
    print("Server Message:", message[2].decode())
    print("\n")
print("Connection Closed")
