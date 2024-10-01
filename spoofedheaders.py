from scapy.all import *
from scapy.utils import wrpcap

base_src_port = 1024

domain_name = "clever-nova"

# Function to simulate TCP handshake, SMTP session, and graceful termination
def build_smtp_session(src_ip, dst_ip, src_port, dst_port):
    packets = []
    for i in range(0, 20):
        # Initial sequence and acknowledgment numbers
        src_port = base_src_port + i * 10
        seq = 1000 + i * 1000
        ack = 2000 + i * 1000
        
        # Step 1: TCP Handshake (SYN, SYN-ACK, ACK)
        syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S', seq=seq)
        syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='SA', seq=2000, ack=syn.seq + 1)
        ack_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=syn.seq + 1, ack=syn_ack.seq + 1)
        
        packets.extend([syn, syn_ack, ack_pkt])
        
        # Update sequence and acknowledgment numbers
        seq = ack_pkt.seq
        ack = syn_ack.seq + 1

        # Step 2: SMTP communication (HELO, MAIL FROM, RCPT TO, DATA, QUIT)
        
        # HELO
        helo = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq, ack=ack) / Raw(load=f'HELO {domain_name}\r\n')
        seq += len(helo[Raw].load)
        packets.append(helo)
        
        # MAIL FROM
        mail_from = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq, ack=ack) / Raw(load=f'MAIL FROM:<spoofed@{domain_name}>\r\n')
        seq += len(mail_from[Raw].load)
        packets.append(mail_from)
        
        # RCPT TO
        rcpt_to = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq, ack=ack) / Raw(load=f'RCPT TO:<victim@{domain_name}>\r\n')
        seq += len(rcpt_to[Raw].load)
        packets.append(rcpt_to)
        
        # DATA command
        data = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq, ack=ack) / Raw(load='DATA\r\n')
        seq += len(data[Raw].load)
        packets.append(data)
        
        # Email body with spoofed headers and failed SPF simulation
        email_headers = (
            f"Subject: {'Urgent Update' if i == 0 else 'Important Notice' if i == 1 else 'Action Required' if i == 2 else 'Account Security Alert' if i == 3 else 'Due Immediately!' if i == 4 else 'Complete ASAP by COB'}\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OWA/15.1.225.42\r\n"
            "x-originating-ip: 8.8.8.8\r\n"
            f"From: {domain_name}-invoices@attacker.com\r\n"
            f"To: victim@{domain_name}.com\r\n"
            "Return-Path: <malicious@gmail.com>\r\n"  # Mismatched Return-Path
            f"Received: from mx.google.com by west-gateapartments.com with SMTP id abc123456; Wed, 22 Sep 2024 10:20:30 -0700\r\n"  # Personal email service identifier
            f"Received: from protection.mail.outlook.com by mx.google.com with SMTP id def789012; Wed, 22 Sep 2024 10:21:00 -0700\r\n"  # Received header with attacker.com domain
            f"Authentication-Results: spf=fail smtp.mailfrom=attacker.com; {domain_name}.com;\r\n"  # SPF failure
            "\r\n"
            "You have several unpaid invoices with a status of \"Awaiting Payment\". Please pay these immediately to avoid missing all deliveries next week!.\r\n"
            ".\r\n"
        )
        
        email_body = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq, ack=ack) / Raw(load=email_headers)
        seq += len(email_body[Raw].load)
        packets.append(email_body)
        
        # QUIT command
        quit_cmd = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq, ack=ack) / Raw(load='QUIT\r\n')
        seq += len(quit_cmd[Raw].load)
        packets.append(quit_cmd)
        
        # Step 3: Graceful TCP termination (FIN-ACK, FIN-ACK, ACK)
        
        # FIN from client
        fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='FA', seq=seq, ack=ack)
        fin_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='FA', seq=ack, ack=fin.seq + 1)
        last_ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=fin.seq + 1, ack=fin_ack.seq + 1)
        
        packets.extend([fin, fin_ack, last_ack])

    # Move the return statement outside the loop to ensure all packets are collected
    return packets

# Function to save packets to a pcap file
def capture_and_save_packets(packets, pcap_file):
    wrpcap(pcap_file, packets)
    print(f"Simulated email traffic saved to {pcap_file}")

# Main function to build packets and simulate the full SMTP session
def main():
    # Simulate a source and destination IP
    src_ip = "192.168.1.100"  # Replace with the desired source IP
    dst_ip = "192.168.1.200"  # Replace with the target server IP
    src_port = 12345  # Random source port
    dst_port = 25     # SMTP port (unencrypted)
    
    # File to save the captured packets
    pcap_file = "domain_name_in_sender_spoofed.pcap"
    
    # Build the full SMTP session packets
    packets = build_smtp_session(src_ip, dst_ip, src_port, dst_port)
    
    # Save packets to pcap file
    capture_and_save_packets(packets, pcap_file)

if __name__ == "__main__":
    main()