import cv2
import logging
import os
import smtplib
from collections import defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from scapy.all import *

# Set the interface to listen on
interface = "{599FE0D6-5663-4DE0-B19B-DCDB9ED48E61}"

# Set the owner's email address
owner_email = "owner@example.com"

# Set the SMTP server and login details for sending email
smtp_server = "smtp.example.com"
smtp_port = 587
smtp_user = "user@example.com"
smtp_password = "password"

# Set the threshold for detecting port scanning and brute-force login attempts
port_scan_threshold = 5
brute_force_threshold = 5

# Initialize counters for port scanning and brute-force login attempts
port_scan_counter = defaultdict(int)
brute_force_counter = defaultdict(int)

def send_email(subject, body, image_filename=None):
    """Send an email to the owner with the given subject and body."""
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = owner_email

    text = MIMEText(body)
    msg.attach(text)

    if image_filename:
        with open(image_filename, 'rb') as f:
            img_data = f.read()
            image = MIMEImage(img_data, name=image_filename)
            msg.attach(image)

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_user, smtp_password)
    server.sendmail(smtp_user, [owner_email], msg.as_string())
    server.quit()

def handle_packet(packet):
    """Handle a captured packet."""
    # Check if the packet is an ICMP echo request (ping)
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        # Get the source IP address of the packet
        src_ip = packet[IP].src

        # Log the ping attempt
        logging.warning(f"Detected ping from {src_ip}")

        # Block incoming traffic from the attacker's IP address
        os.system(f"sudo iptables -A INPUT -s {src_ip} -j DROP")

        # Capture an image using the webcam
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()

        # Save the image to a file
        image_filename = "intruder.jpg"
        cv2.imwrite(image_filename, frame)

        # Send an email to the owner with the details of the ping attempt and the captured image
        subject = f"IDS Alert: Detected and blocked ping from {src_ip}"
        body = f"Detected and blocked a ping attempt from IP address {src_ip} on interface {interface}."
        send_email(subject, body, image_filename)

    # Check if the packet is a TCP SYN packet (indicating a port scan)
    elif packet.haslayer(TCP) and packet[TCP].flags == "S":
        # Get the source IP address and destination port of the packet
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Increment the port scan counter for the source IP address and destination port
        port_scan_counter[(src_ip, dst_port)] += 1

        # Check if the port scan counter has reached the threshold for detecting a port scan
        if port_scan_counter[(src_ip, dst_port)] >= port_scan_threshold:
            # Log the port scan attempt
            logging.warning(f"Detected port scan from {src_ip} on port {dst_port}")

            # Block incoming traffic from the attacker's IP address on the scanned port
            os.system(f"sudo iptables -A INPUT -s {src_ip} -p tcp --dport {dst_port} -j DROP")

            # Send an email to the owner with details of the port scan attempt
            subject = f"IDS Alert: Detected and blocked port scan from {src_ip} on port {dst_port}"
            body = f"Detected and blocked a port scan attempt from IP address {src_ip} on interface {interface}, targeting port {dst_port}."
            send_email(subject, body)

    # Check if the packet is an SSH login attempt (indicating a brute-force login attempt)
    elif packet.haslayer(TCP) and packet[TCP].dport == 22 and packet.haslayer(Raw):
        # Get the source IP address of the packet
        src_ip = packet[IP].src

        # Increment the brute-force login counter for the source IP address
        brute_force_counter[src_ip] += 1

        # Check if the brute-force login counter has reached the threshold for detecting a brute-force login attempt
        if brute_force_counter[src_ip] >= brute_force_threshold:
            # Log the brute-force login attempt
            logging.warning(f"Detected brute-force login attempt from {src_ip}")

            # Block incoming traffic from the attacker's IP address on the SSH port
            os.system(f"sudo iptables -A INPUT -s {src_ip} -p tcp --dport 22 -j DROP")

            # Send an email to the owner with details of the brute-force login attempt
            subject = f"IDS Alert: Detected and blocked brute-force login attempt from {src_ip}"
            body = f"Detected and blocked a brute-force login attempt from IP address {src_ip} on interface {interface}, targeting the SSH port."
            send_email(subject, body)

# Set up logging to a file
logging.basicConfig(filename="ids.log", level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")

# Start sniffing packets on the specified interface
sniff(iface=interface, prn=handle_packet)


# from scapy.all import get_if_list
# print(get_if_list())