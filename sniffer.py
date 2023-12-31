import socket
import struct
import binascii
import threading
import time
from utils import sniffer_utils
import prettytable

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


debugger_file = open("debugger.txt", "w")


def write_to_file_with_limit(path, data, limit):
    file = open(path, "w")
    file.write(data[:limit])
    file.close()

def beatify_arp_table():
    table = prettytable.PrettyTable()
    table.field_names = ["IP", "REQUESTS", "REPLIES"]
    for key, value in dict_arp.items():
        table.add_row([key, value["request"], value["reply"]])
    
    print(table)


def beatify_icmp_table():
    table = prettytable.PrettyTable()
    table.field_names = ["IP", "REQUESTS"]
    for key, value in dict_icmp.items():
        table.add_row([key, value["request"]])
    
    print(table)

def beatify_counts():
    table = prettytable.PrettyTable()
    table.field_names = ["ARP REQUESTS", "ARP REPLIES", "ICMPv4", "ICMPv6", "IPv4", "IPv6", "TCP", "UDP"]
    table.add_row([count_arp_requests, count_arp_replies, count_icmpv4, count_icmpv6, count_ipv4, count_ipv6, count_tcp, count_udp])
    print(table)

def add_to_icmptable(pkt):
    global dict_icmp
    source, dest = sniffer_utils.get_icmp_source_and_target(pkt)
    if (source not in dict_icmp):
        dict_icmp[source] = {"request": 1}
    else:
        dict_icmp[source]["request"] += 1

    check_icmp_counts()




def create_raw_socket():
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    rawSocket.bind(('wlp0s20f3', 0))
    return rawSocket

def clear_icmp_and_arp_tables():
    global dict_icmp, dict_arp
    timer = 10
    while True:
        time.sleep(1)
        timer -= 1
        if timer == 0:
            print("Clearing ICMP and ARP tables")
            beatify_arp_table()
            beatify_icmp_table()
            for key in dict_icmp:
                dict_icmp[key]["request"] = 0
            for key in dict_arp:
                dict_arp[key]["request"] = 0
                dict_arp[key]["reply"] = 0
            timer = 10

def receive_pkg(rawSocket,package_queue):
    global count_arp_requests, count_arp_replies, count_icmpv4, count_icmpv6, count_ipv4, count_ipv6, count_tcp, count_udp
    global dict_arp, dict_icmp
    global debugger_file
    while True:
        pkt = rawSocket.recvfrom(2048)
        package_queue.put(sniffer_utils.format_packet_data(pkt[0]))
        if (sniffer_utils.is_ipv4(pkt[0])):
            count_ipv4 += 1
            if (sniffer_utils.is_icmp(pkt[0])):
                add_to_icmptable(pkt[0])
                count_icmpv4 += 1
                debugger_file.write(sniffer_utils.str_beautify_icmp(pkt[0]) + "\n\n")
            elif (sniffer_utils.is_tcp(pkt[0])):
                count_tcp += 1
                debugger_file.write(sniffer_utils.str_beautify_tcp(pkt[0]) + "\n\n")
            elif (sniffer_utils.is_udp(pkt[0])):
                count_udp += 1
                debugger_file.write(sniffer_utils.str_beautify_udp(pkt[0]) + "\n\n")
            else:
                pass
                #print("Unknown IPv4 protocol")

        if (sniffer_utils.is_ipv6(pkt[0])):
            count_ipv6 += 1
            if (sniffer_utils.is_icmp(pkt[0])):
                count_icmpv6 += 1
                add_to_icmptable(pkt[0])
                debugger_file.write(sniffer_utils.str_beautify_icmp(pkt[0]) + "\n\n")
            elif (sniffer_utils.is_tcp(pkt[0])):
                count_tcp += 1
                debugger_file.write(sniffer_utils.str_beautify_tcp(pkt[0]) + "\n\n")
            elif (sniffer_utils.is_udp(pkt[0])):
                count_udp += 1
                debugger_file.write(sniffer_utils.str_beautify_udp(pkt[0]) + "\n\n")
            else:
                pass
                #print("Unknown IPv6 protocol")

        if (sniffer_utils.is_arp(pkt[0])):
            debugger_file.write(sniffer_utils.str_beautify_arp(pkt[0]) + "\n\n")
            sender_mac, sender_ip, target_mac, target_ip = sniffer_utils.get_arp_sender_and_target(pkt[0])
            if (sniffer_utils.is_arp_request(pkt[0])):
                count_arp_requests += 1
                if (target_ip not in dict_arp):
                    dict_arp[target_ip] = {"request": 1, "reply": 0}
                else:
                    dict_arp[target_ip]["request"] += 1
            elif (sniffer_utils.is_arp_reply(pkt[0])):
                if (sender_ip not in dict_arp):
                    dict_arp[sender_ip] = {"request": 0, "reply": 1}
                else:
                    dict_arp[sender_ip]["reply"] += 1
                count_arp_replies += 1
            else:
                pass
                #print("Unknown ARP packet")
            check_arp_counts()

def check_arp_counts():
    global dict_arp
    for key in dict_arp:
        if ((dict_arp[key]["request"] + 1) * 3 < dict_arp[key]["reply"]):
            #print("ARP spoofing detected IP: %s" % key)
            return True
    return False

def check_icmp_counts():
    global dict_icmp
    for key in dict_icmp:
        if ((dict_icmp[key]["request"] + 1) > 1000):
            #print("ICMP flooding detected IP: %s" % key)
            return True
    return False


def timer_to_print_counts():
    global count_arp_requests, count_arp_replies, count_icmpv4, count_icmpv6, count_ipv4, count_ipv6, count_tcp, count_udp
    while True:
        time.sleep(10)
        beatify_counts()


threading.Thread(target=timer_to_print_counts).start()