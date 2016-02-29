#!/usr/bin/python
"""
anti_vm_defense.py: Used to emulate virtual NAT so that all Anti VM techniques
that are based on virtual NAT behavior will return that the malware is running
inside virtual machine.
"""

from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.sendrecv import send
from scapy import route
from scapy.layers.inet import TCP, IP
from os import system
from netfilterqueue import NetfilterQueue


RST = 0x04


def get_new_ttl(curr_ttl):
    """
    If Windows TTL change to Linux and vice versa.

    :param curr_ttl: Current packet TTL.
    :return: int
    """
    return 64 if curr_ttl == 128 else 128


def handle_packet(pkt):
    """
    Apply packet handling logic.

    :param pkt: Received packet from network.
    """
    global id_counter
    scapy_packet = IP(pkt.get_payload())
    if IP in scapy_packet:
        scapy_packet[IP].ttl = get_new_ttl(scapy_packet[IP].ttl)
        scapy_packet[IP].id = id_counter
        # Change IP ID as Virtual NAT on Windows Host would do.
        id_counter += 1
        if TCP in scapy_packet and scapy_packet[TCP].flags & RST:
            scapy_packet[TCP].flags = 'FA'
        del scapy_packet[IP].chksum
        send(scapy_packet)
        print 'Drop Packet'
        pkt.drop()
    else:
        print 'Accept Packet'
        pkt.accept()


if __name__ == '__main__':
    system('iptables -A OUTPUT -j NFQUEUE --queue-num 1')
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, handle_packet)
    id_counter = 1000
    try:
        print 'Start changing packets as Virtual NAT ...'
        nfqueue.run()
    except KeyboardInterrupt:
        system('iptables -F')
        system('iptables -X')
        nfqueue.unbind()

