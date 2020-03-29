import sys
from scapy.all import sr1, IP, ICMP, send, sniff, AsyncSniffer
import random

addr = sys.argv[1]  # Address to bounce packets off
n = int(sys.argv[2])  # Length of list to be sorted

# Currently sorting a list from 1..n inclusive
# Sorting non-consecutive numbers would be cruel to the network
list_to_sort = list(range(n + 1))[1:]
random.shuffle(list_to_sort)

sorted_list = list()

# Global registers
counter = 0
value = 0
phase = 0


# Function called by sniff
# Calls `process_echo` for ICMP echo reply messages and ignores rest.
def process(packet):
    if packet.payload.type == 0:
        process_echo(packet)


# Convert bytes to int
def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')


# Processes echo reply packets
def process_echo(packet):
    global phase
    global counter
    global value

    data = bytes_to_int(packet.load)
    # Phase 0 corresponds to the phase where the initial wave of
    # packets is being created.
    # Phase ends when ICMP packets corresponding to every number in
    # the list to be sorted are created and boom boomed to the router.
    if phase == 0:
        send_ping1(data)
        # Initial wave of packets have been sent. Switch to phase 1.
        if counter == n - 1:
            phase = 1
    else:
        # Got highest number. Add to sorted_list.
        if int(data) == value:
            print(value)
            value -= 1
            sorted_list.append(data)
        # Keep wrecking the network
        else:
            send_ping1(data)


# Subsequent waves of ICMP packets which doesn't alter the global state
# but simply bounces back every packet.
def send_ping1(data):
    data_bytes = data.to_bytes(16, byteorder='big')
    send(IP(dst=addr) / ICMP() / data_bytes)


# Create the initial wave of ICMP packets which updates value and counter with every call.
def send_ping(data):
    global value
    global counter

    value = max(value, data)
    counter += 1
    data_bytes = data.to_bytes(16, byteorder='big')
    send(IP(dst=addr) / ICMP() / data_bytes)


# Stop sniffing for packets when sorted_list is full.
def stop(pkt):
    global sorted_list
    return len(sorted_list) == n


# Create a sniffer which listens on some interface for icmp packets
t = AsyncSniffer(iface="en0", filter="icmp",
                 prn=process, store=False, stop_filter=stop)
# Start sniffing
t.start()

for num in list_to_sort:
    send_ping(num)
# Wait for the list to get sorted while the creator of ICMP rolls in his grave.
t.join()
print(sorted_list)
