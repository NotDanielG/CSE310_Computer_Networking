import dpkt

file = dpkt.pcap.Reader(open('assignment4_example.pcap', 'rb'))

arps = list()
for time, info in file:
    if info[12:14] == b'\x08\06':  # Checks if packet is an ARP, if so added to the list
        arps.append(info)
if len(arps) >= 2:  # Checks to see if there are at least 2 ARPs in the list
    packets = (arps[0], arps[1])
    print('Sender:')  #
    hardware = int.from_bytes(arps[0][14:16], 'big', signed=False)
    #if hardware == 1:  # Checks if hardware type is an ethernet and sets it to a string, else it just prints the int
    #    hardware = 'Ethernet'
    print('Hardware Type:', 'Ethernet', hardware)
    protocol = int.from_bytes(arps[0][16:18], 'big', signed=False)
    if protocol == 2048:  # Checks to see if protocol type is IPv4, else prints value
        protocol = 'IPv4'
    print('Protocol Type:', protocol)
    print('Hardware Size:', int.from_bytes(arps[0][18:19], 'big', signed=False))  # Prints hardware size
    print('Protocol Size:', int.from_bytes(arps[0][19:20], 'big', signed=False))  # Prints protocol size
    request_opcode = int.from_bytes(arps[0][20:22], 'big', signed=False)
    type = ''
    if request_opcode == 1:  # Determines whether opcode is request or reply
        type = 'request'
    else:
        type = 'reply'
    print('Opcode:', type, request_opcode)
    i = 22
    sender_mac = ''
    while i != 28: # parses from 22:28, turns the byte to a hexadecimal and adds it to string
        piece = arps[0][i:i+1].hex()
        sender_mac += piece
        if i != 27:
            sender_mac += ':'
        i+=1
    print('Sender Mac Address:', sender_mac)

    sender_ip = ''
    i = 28
    while i != 32:  #28:32
        piece = int.from_bytes(arps[0][i:i+1], 'big', signed=False)
        sender_ip += str(piece)
        if i != 31:
            sender_ip += '.'
        i += 1
    print('Sender IP Address:', sender_ip)
    i = 32
    target_mac = ''
    while i != 38: # 32:38
        piece = arps[0][i:i+1].hex()
        target_mac += piece
        if i != 37:
            target_mac += ':'
        i+=1
    print('Target Mac Address:', target_mac)
    target_ip = ''
    i = 38
    while i != 42:  #38:42
        piece = int.from_bytes(arps[0][i:i+1], 'big', signed=False)
        target_ip += str(piece)
        if i != 41:
            target_ip += '.'
        i += 1
    print('Target IP Address:', target_ip, '\n')

    print('Reply:')  # Receiver, the 2nd packet --------------------------------------------------------------------
    hardware = int.from_bytes(arps[1][14:16], 'big', signed=False)
    #if hardware == 1:
    #    hardware = 'Ethernet'
    print('Hardware Type:', 'Ethernet', hardware)
    protocol = int.from_bytes(arps[1][16:18], 'big', signed=False)
    if protocol == 2048:
        protocol = 'IPv4'
    print('Protocol Type:', protocol)
    print('Hardware Size:', int.from_bytes(arps[1][18:19], 'big', signed=False))
    print('Protocol Size:', int.from_bytes(arps[1][19:20], 'big', signed=False))
    request_opcode = int.from_bytes(arps[1][20:22], 'big', signed=False)
    type = ''
    if request_opcode == 1:
        type = 'request'
    else:
        type = 'reply'
    print('Opcode:', type, request_opcode)
    i = 22
    sender_mac = ''
    while i != 28: # 22:28
        piece = arps[1][i:i+1].hex()
        sender_mac += piece
        if i != 27:
            sender_mac += ':'
        i+=1
    print('Sender Mac Address:', sender_mac)

    sender_ip = ''
    i = 28
    while i != 32:  #28:32
        piece = int.from_bytes(arps[1][i:i+1], 'big', signed=False)
        sender_ip += str(piece)
        if i != 31:
            sender_ip += '.'
        i += 1
    print('Sender IP Address:', sender_ip)

    i = 32
    target_mac = ''
    while i != 38: # 32:38
        piece = arps[1][i:i+1].hex()
        target_mac += piece
        if i != 37:
            target_mac += ':'
        i+=1
    print('Target Mac Address:', target_mac)

    target_ip = ''
    i = 38
    while i != 42:  #38:42
        piece = int.from_bytes(arps[1][i:i+1], 'big', signed=False)
        target_ip += str(piece)
        if i != 41:
            target_ip += '.'
        i += 1
    print('Target IP Address:', target_ip)
