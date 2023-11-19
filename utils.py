import binascii
import socket
import struct


class sniffer_utils:
    @staticmethod
    def is_arp(pkt):
        return pkt[12:14] == b'\x08\x06'

    @staticmethod
    def is_icmp(pkt):
        return sniffer_utils.is_ipv4(pkt) and pkt[23] == 1

    @staticmethod
    def is_icmpv6(pkt):
        return sniffer_utils.is_ipv6(pkt) and pkt[20] == 58

    @staticmethod
    def is_ipv4(pkt):
        return pkt[12:14] == b'\x08\x00'

    @staticmethod
    def is_ipv6(pkt):
        return pkt[12:14] == b'\x86\xdd'

    @staticmethod
    def is_tcp(pkt):
        return pkt[23] == 6

    @staticmethod
    def is_udp(pkt):
        return pkt[23] == 17

    @staticmethod
    def get_source_mac(pkt):
        return binascii.hexlify(pkt[6:12]).decode('utf-8')

    @staticmethod
    def get_dest_mac(pkt):
        return binascii.hexlify(pkt[0:6]).decode('utf-8')

    @staticmethod
    def get_eth_type(pkt):
        return binascii.hexlify(pkt[12:14]).decode('utf-8')

    @staticmethod
    def get_source_ip_ipv4(pkt):
        return socket.inet_ntoa(pkt[26:30])

    @staticmethod
    def get_dest_ip_ipv4(pkt):
        return socket.inet_ntoa(pkt[30:34])

    @staticmethod
    def get_source_ip_ipv6(pkt):
        return socket.inet_ntop(socket.AF_INET6, pkt[22:38])

    @staticmethod
    def get_dest_ip_ipv6(pkt):
        return socket.inet_ntop(socket.AF_INET6, pkt[38:54])

    @staticmethod
    def get_source_ip(pkt):
        if sniffer_utils.is_ipv4(pkt):
            return sniffer_utils.get_source_ip_ipv4(pkt)
        elif sniffer_utils.is_ipv6(pkt):
            return sniffer_utils.get_source_ip_ipv6(pkt)
        else:
            return None

    @staticmethod
    def get_dest_ip(pkt):
        if sniffer_utils.is_ipv4(pkt):
            return sniffer_utils.get_dest_ip_ipv4(pkt)
        elif sniffer_utils.is_ipv6(pkt):
            return sniffer_utils.get_dest_ip_ipv6(pkt)
        else:
            return None

    @staticmethod
    def get_source_port(pkt):
        return struct.unpack('!H', pkt[34:36])[0]

    @staticmethod
    def get_dest_port(pkt):
        return struct.unpack('!H', pkt[36:38])[0]

    @staticmethod
    def get_icmp_type_ipv4(pkt):
        return struct.unpack('!B', pkt[34:35])[0]

    @staticmethod
    def get_icmp_code_ipv4(pkt):
        return struct.unpack('!B', pkt[35:36])[0]

    @staticmethod
    def get_icmp_type_ipv6(pkt):
        return struct.unpack('!B', pkt[54:55])[0]

    @staticmethod
    def get_icmp_code_ipv6(pkt):
        return struct.unpack('!B', pkt[55:56])[0]
    
    @staticmethod
    def get_arp_operation(pkt):
        return struct.unpack('!H', pkt[20:22])[0]

    @staticmethod
    def get_icmp_type(pkt):
        if sniffer_utils.is_ipv4(pkt):
            return sniffer_utils.get_icmp_type_ipv4(pkt)
        elif sniffer_utils.is_ipv6(pkt):
            return sniffer_utils.get_icmp_type_ipv6(pkt)
        else:
            return None

    @staticmethod
    def get_icmp_code(pkt):
        if sniffer_utils.is_ipv4(pkt):
            return sniffer_utils.get_icmp_code_ipv4(pkt)
        elif sniffer_utils.is_ipv6(pkt):
            return sniffer_utils.get_icmp_code_ipv6(pkt)

    @staticmethod
    def str_beautify_tcp(pkt):
        ip_version = 'IPv4' if sniffer_utils.is_ipv4(pkt) else 'IPv6'
        return "IP Version: %s, Source MAC: %s, Destination MAC: %s, Source IP: %s, Destination IP: %s, Source Port: %s, Destination Port: %s, TCP Flags: %s" % (
            ip_version,
            sniffer_utils.get_source_mac(pkt),
            sniffer_utils.get_dest_mac(pkt),
            sniffer_utils.get_source_ip(pkt),
            sniffer_utils.get_dest_ip(pkt),
            sniffer_utils.get_source_port(pkt),
            sniffer_utils.get_dest_port(pkt),
            binascii.hexlify(pkt[47:48]).decode('utf-8') if sniffer_utils.is_tcp(pkt) else 'N/A'
        )

    @staticmethod
    def str_beautify_udp(pkt):
        ip_version = 'IPv4' if sniffer_utils.is_ipv4(pkt) else 'IPv6'
        return "IP Version: %s, Source MAC: %s, Destination MAC: %s, Source IP: %s, Destination IP: %s, Source Port: %s, Destination Port: %s" % (
            ip_version,
            sniffer_utils.get_source_mac(pkt),
            sniffer_utils.get_dest_mac(pkt),
            sniffer_utils.get_source_ip(pkt),
            sniffer_utils.get_dest_ip(pkt),
            sniffer_utils.get_source_port(pkt),
            sniffer_utils.get_dest_port(pkt)
        )

    @staticmethod
    def str_beautify_icmp(pkt):
        ip_version = 'IPv4' if sniffer_utils.is_ipv4(pkt) else 'IPv6'
        return "IP Version: %s, Source MAC: %s, Destination MAC: %s, Source IP: %s, Destination IP: %s, ICMP Type: %s, ICMP Code: %s" % (
            ip_version,
            sniffer_utils.get_source_mac(pkt),
            sniffer_utils.get_dest_mac(pkt),
            sniffer_utils.get_source_ip(pkt),
            sniffer_utils.get_dest_ip(pkt),
            sniffer_utils.get_icmp_type(pkt),
            sniffer_utils.get_icmp_code(pkt)
        )

    @staticmethod
    def str_beautify_arp(pkt):
        return "Source MAC: %s, Destination MAC: %s, Source IP: %s, Destination IP: %s ARP Operation: %s" % (
            sniffer_utils.get_source_mac(pkt),
            sniffer_utils.get_dest_mac(pkt),
            sniffer_utils.get_source_ip(pkt),
            sniffer_utils.get_dest_ip(pkt),
            sniffer_utils.get_arp_operation(pkt)
        )