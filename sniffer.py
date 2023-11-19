import socket
import struct
import binascii
import threading
import time
from utils import sniffer_utils

count_arp_requests = 0
count_arp_replies = 0

count_icmpv4 = 0
count_icmpv6 = 0
count_ipv4 = 0
count_ipv6 = 0

count_tcp = 0
count_udp = 0

dict_arp = {}
dict_icmp = {}




def add_to_arptable(pkt):
    global dict_arp
    arp_hdr = pkt[14:42]
    arp_hdr = struct.unpack("!2s2s1s1s2s6s4s6s4s", arp_hdr)
    ip_addr = socket.inet_ntoa(arp_hdr[6])
    mac_addr = binascii.hexlify(arp_hdr[5]).decode('utf-8')
    if ip_addr not in dict_arp:
        dict_arp[ip_addr] = [[mac_addr, [time.time()]]]
        print("IP: %s MAC: %s" % (ip_addr, mac_addr))
    else:
        if mac_addr not in dict_arp[ip_addr]:
            dict_arp[ip_addr].append([mac_addr, [time.time()]])
            print("IP: %s MAC: %s" % (ip_addr, mac_addr))


def add_to_icmptable(pkt):
    global dict_icmp
    ip_hdr = pkt[14:34]
    ip_hdr = struct.unpack("!12s4s4s", ip_hdr)
    ip_addr = socket.inet_ntoa(ip_hdr[1])
    if ip_addr not in dict_icmp:
        dict_icmp[ip_addr] = [time.time()]
    else:
        dict_icmp[ip_addr].append(time.time())


rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
rawSocket.bind(("wlp0s20f3", 0x0800))

def receive_pkg():
    global count_arp_requests, count_arp_replies, count_icmpv4, count_icmpv6, count_ipv4, count_ipv6, count_tcp, count_udp
    global dict_arp, dict_icmp
    debugger_file = open("debugger.txt", "w")
    while True:
        pkt = rawSocket.recvfrom(2048)
        if (sniffer_utils.is_ipv4(pkt[0])):
            count_ipv4 += 1
            if (sniffer_utils.is_icmp(pkt[0])):
                count_icmpv4 += 1
                add_to_icmptable(pkt[0])
                print(sniffer_utils.str_beautify_icmp(pkt[0]))
                debugger_file.write(sniffer_utils.str_beautify_icmp(pkt[0]) + "\n\n")
            elif (sniffer_utils.is_tcp(pkt[0])):
                count_tcp += 1
                #debugger_file.write(sniffer_utils.str_beautify_tcp(pkt[0]) + "\n\n")
            elif (sniffer_utils.is_udp(pkt[0])):
                count_udp += 1
                debugger_file.write(sniffer_utils.str_beautify_udp(pkt[0]) + "\n\n")
            else:
                print("Unknown IPv4 protocol")

        elif (sniffer_utils.is_ipv6(pkt[0])):
            count_ipv6 += 1
            if (sniffer_utils.is_icmp(pkt[0])):
                count_icmpv6 += 1
                add_to_icmptable(pkt[0])
                print(sniffer_utils.str_beautify_icmp(pkt[0]))
                debugger_file.write(sniffer_utils.str_beautify_icmp(pkt[0]) + "\n\n")

            elif (sniffer_utils.is_tcp(pkt[0])):
                count_tcp += 1
                debugger_file.write(sniffer_utils.str_beautify_tcp(pkt[0]) + "\n\n")
            elif (sniffer_utils.is_udp(pkt[0])):
                count_udp += 1
                debugger_file.write(sniffer_utils.str_beautify_udp(pkt[0]) + "\n\n")
            else:
                print("Unknown IPv6 protocol")

        elif (sniffer_utils.is_arp(pkt[0])):
            debugger_file.write(sniffer_utils.str_beautify_arp(pkt[0]) + "\n\n")
            if (sniffer_utils.is_arp_request(pkt[0])):
                count_arp_requests += 1
            elif (sniffer_utils.is_arp_reply(pkt[0])):
                count_arp_replies += 1
                add_to_arptable(pkt[0])
            else:
                print("Unknown ARP packet")


thread = threading.Thread(target=receive_pkg)
thread.start()
thread.join()