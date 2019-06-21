import dpkt

class Packet:  # Packet from Wireshark
    def __init__(self, info, counter, time):
        self.length = len(info)  # Length of the packet
        self.counter = counter
        self.time = time
        self.ethernet = info[0:14]

        self.IPv4 = info[14:34]  # IPv4 section
        self.TTL = self.IPv4[8]
        self.protocol = self.IPv4[9]
        self.sourceIP = self.IPv4[12:16]
        self.destIP = self.IPv4[16:20]

        self.TCP = info[34:self.length]  # TCP section
        self.sourcePort = self.TCP[0:2]
        self.destPort = self.TCP[2:4]
        self.seq = self.TCP[4:8]
        self.ack = self.TCP[8:12]
        self.flags = self.TCP[12:14]
        self.window = self.TCP[14:16]
        self.checksum = self.TCP[16:18]
        self.shift = info[self.length-1]  # shift to calculate rwnd

class Flow:
    def __init__(self, packet: 'Packet'):
        self.srcPort = packet.sourcePort
        self.destPort = packet.destPort
        self.packets = [packet]
        self.first = packet

    def add_packet(self, packet: 'Packet'):  # Adds packet to list
        self.packets.append(packet)

    def same_flow(self, packet: 'Packet'):  # Sees if same port and destination, then calculates vice versa as well
        return (self.srcPort == packet.sourcePort and self.destPort == packet.destPort) or \
               (self.srcPort == packet.destPort and self.destPort == packet.sourcePort)

    def display_flow(self):
        print("Sender:", int.from_bytes(self.srcPort, 'big', signed=False), "Receiver", int.from_bytes(self.destPort, 'big', signed=False))

    def display(self, integer):
        return ('SEQ: ' + str(int.from_bytes(self.packets[integer].seq, 'big', signed=False)),
                'ACK: ' + str(int.from_bytes(self.packets[integer].ack, 'big', signed=False)),
                'RWND: ' + str(int.from_bytes(self.packets[integer].window, 'big', signed=False)))


file = dpkt.pcap.Reader(open('assignment3.pcap', 'rb'))

count = 1
flow = 0
flows = list()
for time, info in file:  # this for loop creates the 3 flows
    pack = Packet(info, count, time)
    count += 1
    if len(flows) == 0:
        flow = Flow(pack)
        flows.append(flow)
    else:
        counter = 0
        for flow in flows:
            if flow.same_flow(pack):  # To see if it is in the same flow as ones already in the list
                flow.add_packet(pack)
                break
            counter += 1
        if counter == len(flows):  # Adds new flow to the list
            flow = Flow(pack)
            flows.append(flow)

print("Amount of flow:", len(flows))
for flow in flows:
    flow.display_flow()
    i = 0
    idx = 3
    while i < 2:
        if flow.srcPort == flow.packets[idx].sourcePort:
            print("SEQ:", str(int.from_bytes(flow.packets[idx].seq, 'big', signed=False)),
                  "ACK:", str(int.from_bytes(flow.packets[idx].ack, 'big', signed=False)),
                  "RWND:", str(2**int(flow.first.shift)*int.from_bytes(flow.packets[idx].window, 'big', signed=False)))
                  #"No.", flow.packets[idx].counter)
            i += 1
        idx += 1
    idx = 3  # Start after the handshake
    sum = 0
    while idx < len(flow.packets)-2:  # -2 for the sender's last FIN packet, cause flow contains tcp to and from for sender & destination
        sum += flow.packets[idx].length  # Added the the length of each entire packet
        idx+=1
    print("Throughput:", sum)

    sent = 0
    received = 0
    idx = 3
    while idx < len(flow.packets)-1:
        if flow.packets[idx].sourcePort == flow.srcPort:
            sent += 1
        else:
            received += 1
        idx+=1
    print("Sent:", sent, "Received:", received)
    difference = sent-received  # number of packets not received
    loss_rate = difference/sent
    print("Loss Rate:", loss_rate)  # loss rate is the loss packets divided by the amount, this includes duplicate packets
    cwnd = 0
    idx = 3
    count = 0
    time_start = 0
    time_end = 0
    rtt = 0
    while count < 5 and idx < len(flow.packets):
        save = 0
        while flow.packets[idx].sourcePort != flow.srcPort:  # Finds when the next idx
            idx += 1
        if count == 0:  # only for the inital cwnd
            time_start = flow.packets[idx].time
            store = flow.packets[idx+1].seq
            save = idx+2
        else:  # store_cwnd for the case in the first flow
            store = flow.packets[idx].seq
            save = idx+1
            store_cwnd = cwnd
        while int.from_bytes(flow.packets[idx].ack, 'big', signed=False) != \
                int.from_bytes(store, 'big', signed=False):  # Adds to cwnd
            cwnd += flow.packets[idx].length
            idx += 1
            if idx >= len(flow.packets):  # There was one case in the first flow where a packet is sent
                # but never receives anything back, no retransmission was sent either
                # Fix to the infinite loop
                idx = save
                cwnd = store_cwnd
                save += 1
                store = flow.packets[idx].seq
        if count == 0:  # calculate rtt for next part
            time_end = flow.packets[idx].time
            #print(time_start, time_end, idx)
            rtt = time_end - time_start

        print("CWND:", cwnd)
        count += 1
    #print(rtt)
    #Part B2
    tested_triples = []  # two list to store already retransmitted
    tested_timeout = []
    idx = 4  # starts at 4 past handshake
    ack = flow.packets[3].ack
    #print(int.from_bytes(ack, 'big', signed=False))
    while idx < len(flow.packets):
        testing = flow.packets[idx]  # Testing packet we are testing
        duplicate = False
        triple = 0
        timeout = 0
        while i < len(tested_triples):
            if int.from_bytes(testing.seq, 'big', signed=False) == \
                    int.from_bytes(tested_triples[i].seq, 'big', signed=False) and int.from_bytes(testing.ack, 'big', signed=False) == int.from_bytes(tested_triples[i].ack, 'big', signed=False):
                duplicate = True
                break
            i += 1
        i = 0
        while i < len(tested_timeout):
            if int.from_bytes(testing.seq, 'big', signed=False) == \
                    int.from_bytes(tested_timeout[i].seq, 'big', signed=False) and int.from_bytes(testing.ack, 'big', signed=False) == int.from_bytes(tested_timeout[i].ack, 'big', signed=False):
                duplicate = True
                break
            i += 1
        #last two while loops are for testing if a retransmission already happened
        if not duplicate:
            inner_idx = idx + 1
            for_timeout = 0
            #Checks within the timeframe of rtt
            while inner_idx < len(flow.packets)-2 and flow.packets[inner_idx].time - testing.time < rtt:
                if int.from_bytes(testing.seq, 'big', signed=False) == int.from_bytes(flow.packets[inner_idx].seq,'big',signed=False) and int.from_bytes(testing.ack, 'big', signed=False) == int.from_bytes(flow.packets[inner_idx].ack,'big',signed=False):
                    triple += 1
                    for_timeout = inner_idx
                    #print(testing.counter, flow.packets[inner_idx].counter)
                if triple >= 3:
                    #print(int.from_bytes(flow.packets[inner_idx].checksum,'big',signed=False), flow.packets[inner_idx].counter)
                    tested_triples.append(testing)
                    break
                inner_idx+=1
            if 0 < triple < 3:
                tested_timeout.append(testing)
        idx += 1

    print("Triple Retransmission:", len(tested_triples), "Timeout:", len(tested_timeout))

    print('\n')
