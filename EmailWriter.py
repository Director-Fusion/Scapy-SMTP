import requests
from scapy.all import *
from scapy.utils import wrpcap
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random
import base64
import mimetypes

# Step 1: Download the URLhaus RPZ file
rpz_url = "https://urlhaus.abuse.ch/downloads/rpz/"
response = requests.get(rpz_url)
if response.status_code != 200:
    raise Exception(f"Failed to download RPZ file: {response.status_code}")

# Step 2: Parse the RPZ file to extract domains
domains = []
for line in response.text.splitlines():
    if line and not line.startswith(';') and 'CNAME' in line:
        domain = line.split()[0]
        domains.append(domain)

# Step 3: Create email packets and write to PCAP
pcap_file = "replies.pcap"
pcap_file2 = "attachment.pcap"
pkts = []
domain_name = "clever-nova.com"

src_ip = "10.11.75.222"  # Sender IP
dst_ip = "10.11.76.25"  # Receiver IP

def emails_w_http():
    
    for i, domain in enumerate(domains):
        dst_port = 25
        base_src_port = 1024
        subject = "Important Security Update"
        body = f"Please visit the following link for more details: http://{domain}"
        to_email = "victim@victim-org.com"
        from_email = "evil@evil-org.com"
        if "testentry.rpz.urlhaus.abuse.ch" in domain:
            pass
        else:
            # Create email content
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Convert email to bytes
            email_bytes = msg.as_bytes()
            
            # Use a different source port for each email to simulate separate connections
            src_port = base_src_port + i * 10
            seq = 1000 + i * 1000
            ack = 2000 + i * 1000
            
            # TCP handshake
            syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S', seq=seq)
            syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='SA', seq=ack, ack=syn.seq + 1)
            ack_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=syn.seq + 1, ack=syn_ack.seq + 1)
            
            pkts.extend([syn, syn_ack, ack_pkt])
            helo = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1, ack=syn_ack.seq + 1) / Raw(load="HELO evil.org\r\n")
            helo_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1, ack=syn.seq + 1 + len("HELO evil.org\r\n")) / Raw(load="250 Hello evil.org\r\n")
            
            mail_from = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO evil.org\r\n"), ack=syn_ack.seq + 1 + len("250 Hello evil.org\r\n")) / Raw(load=f"MAIL FROM:<{from_email}>\r\n")
            mail_from_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello evil.org\r\n"), ack=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n")) / Raw(load="250 OK\r\n")
            
            rcpt_to = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n"), ack=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n")) / Raw(load=f"RCPT TO:<{to_email}>\r\n")
            rcpt_to_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n"), ack=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n")) / Raw(load="250 OK\r\n")
            
            data_cmd = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n"), ack=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n") + len("250 OK\r\n")) / Raw(load="DATA\r\n")
            data_cmd_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n") + len("250 OK\r\n"), ack=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n") + len("DATA\r\n")) / Raw(load="354 End data with <CR><LF>.<CR><LF>\r\n")
            
            data = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n") + len("DATA\r\n"), ack=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n")) / Raw(load=email_bytes + b"\r\n.\r\n")
            data_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n"), ack=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n")) / Raw(load="250 OK\r\n")
            
            quit_cmd = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n"), ack=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n") + len("250 OK\r\n")) / Raw(load="QUIT\r\n")
            quit_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n") + len("250 OK\r\n"), ack=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n")) / Raw(load="QUIT\r\n")
            
            pkts.extend([helo, helo_resp, mail_from, mail_from_resp, rcpt_to, rcpt_to_resp, data_cmd, data_cmd_resp, data, data_resp, quit_cmd, quit_resp])
            
            # TCP FIN, FIN ACK, and ACK packets
            fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='FA', seq=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n"), ack=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n") + len("250 OK\r\n"))
            fin_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='FA', seq=syn_ack.seq + 1 + len("250 Hello evil.org\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n") + len("250 OK\r\n"), ack=syn.seq + 1 + len("HELO evil.org\r\n") + len(f"MAIL FROM:<{from_email}>\r\n") + len(f"RCPT TO:<{to_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n"))
            ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=fin.seq + 1, ack=fin_ack.seq + 1)
            
            pkts.extend([fin, fin_ack, ack])
            
            # Randomize HTTP creation with a random number between 0-5
            random_num = random.randint(0, 6)
            
            # If the random number is 1 or 4, create an HTTP request
            if random_num in [1, 6]:
                
                # TCP handshake packets
                syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S', seq=seq)
                syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='SA', seq=ack, ack=syn[TCP].seq + 1)
                ack_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=syn[TCP].seq + 1, ack=syn_ack[TCP].seq + 1)

                pkts.extend([syn, syn_ack, ack_pkt])
                helo = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn[TCP].seq + 1, ack=syn_ack[TCP].seq + 1) / Raw(load=f"HELO clever-nova.com\r\n")
                helo_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack[TCP].seq + 1, ack=syn[TCP].seq + 1 + len(f"HELO clever-nova.com\r\n")) / Raw(load="250 Hello clever-nova.com\r\n")
                
                mail_from = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO clever-nova.com\r\n"), ack=syn_ack.seq + 1 + len("250 Hello clever-nova.org\r\n")) / Raw(load=f"MAIL FROM:<{to_email}>\r\n")
                mail_from_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n"), ack=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n")) / Raw(load="250 OK\r\n")
                
                rcpt_to = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n"), ack=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n")) / Raw(load=f"RCPT TO:<{from_email}>\r\n")
                rcpt_to_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n"), ack=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n")) / Raw(load="250 OK\r\n")
                
                data_cmd = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n"), ack=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n") + len("250 OK\r\n")) / Raw(load="DATA\r\n")
                data_cmd_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n") + len("250 OK\r\n"), ack=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n") + len("DATA\r\n")) / Raw(load="354 End data with <CR><LF>.<CR><LF>\r\n")
                
                data = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n") + len("DATA\r\n"), ack=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n")) / Raw(load=email_bytes + b"\r\n.\r\n")
                data_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n"), ack=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n")) / Raw(load="250 OK\r\n")
                
                quit_cmd = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n"), ack=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n") + len("250 OK\r\n")) / Raw(load="QUIT\r\n")
                quit_resp = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n") + len("250 OK\r\n"), ack=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n")) / Raw(load="QUIT\r\n")
                
                pkts.extend([helo, helo_resp, mail_from, mail_from_resp, rcpt_to, rcpt_to_resp, data_cmd, data_cmd_resp, data, data_resp, quit_cmd, quit_resp])
                
                # TCP FIN, FIN ACK, and ACK packets
                fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='FA', seq=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n"), ack=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n") + len("250 OK\r\n"))
                fin_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='FA', seq=syn_ack.seq + 1 + len("250 Hello clever-nova.com\r\n") + len("250 OK\r\n") + len("250 OK\r\n") + len("354 End data with <CR><LF>.<CR><LF>\r\n") + len("250 OK\r\n"), ack=syn.seq + 1 + len("HELO clever-nova.com\r\n") + len(f"MAIL FROM:<{to_email}>\r\n") + len(f"RCPT TO:<{from_email}>\r\n") + len("DATA\r\n") + len(email_bytes + b"\r\n.\r\n"))
                ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=fin.seq + 1, ack=fin_ack.seq + 1)
                
                pkts.extend([fin, fin_ack, ack])
                # # HTTP TCP handshake
                # seq = 5000
                # ack = 6000
                # src_port = 39999
                # dst_port = 80
                # http_syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S', seq=seq)
                # http_syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='SA', seq=ack, ack=http_syn.seq + 1)
                # http_ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=http_syn.seq + 1, ack=http_syn_ack.seq + 1)

                # pkts.extend([http_syn, http_syn_ack, http_ack])

                # # HTTP GET request
                # http_request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: CustomClient/1.0\r\nAccept: */*\r\n\r\n"
                # http_get = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=http_ack.seq, ack=http_syn_ack.seq + 1) / Raw(load=http_request)
                # pkts.append(http_get)

                # # HTTP response
                # http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n<html>Test</html>\r\n"
                # http_response_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=http_syn_ack.seq + 1, ack=http_get.seq + len(http_request)) / Raw(load=http_response)
                # pkts.append(http_response_pkt)

                # # HTTP session termination (FIN-ACK)
                # http_fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='FA', seq=http_get.seq + len(http_request), ack=http_response_pkt.seq + len(http_response))
                # http_fin_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='FA', seq=http_response_pkt.seq + len(http_response), ack=http_fin.seq + 1)
                # http_ack_fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=http_fin.seq + 1, ack=http_fin_ack.seq + 1)

                # pkts.extend([http_fin, http_fin_ack, http_ack_fin])
            
            else:
                pass
            
        # Limit the number of packets for demonstration purposes (e.g., 10 emails)
        if i >= 99:
            break

        # Write packets to PCAP file
        wrpcap(pcap_file, pkts)
        #print(f"PCAP file '{pcap_file}' generated successfully with {len(pkts)} packets.")
    
def main():
    emails_w_http()
    
main()