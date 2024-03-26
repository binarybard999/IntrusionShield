import os
import time
import socket
import smtplib
import pathlib
import platform
import threading
import subprocess
from mss import mss
from datetime import datetime
from collections import defaultdict
from scapy.all import TCP, ICMP, IP, Raw, sniff
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Configuration
owner_email = "owner@example.com"
sender_email = "your_email@gmail.com"
sender_password = "your_password"
log_file = "security_script_logs.txt"
screenshot_interval = 900  # 15 minutes = 900 seconds
current_platform = platform.system()

if current_platform == "Windows":
    clear_command = "cls"
    firewall_rule_command = "netsh advfirewall firewall"
    interface = "Ethernet"  # Modify with your Windows-specific interface name
else:
    clear_command = "clear"
    firewall_rule_command = "iptables"
    interface = "eth0"  # Modify with your Linux/Unix-specific interface name

# IDS/IPS Configuration
port_scan_threshold = 5
brute_force_threshold = 5
port_scan_counter = defaultdict(int)
brute_force_counter = defaultdict(int)
ips_enabled = True
blacklist_file = "blacklist.txt"
blacklist = set()
# Create a dictionary to keep track of the number of attempts from each IP address
attempt_counter = defaultdict(int)
# Keep track of blocked IP addresses
blocked_ips = set()


# Function to send email
def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = owner_email

        text = MIMEText(body)
        msg.attach(text)

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, owner_email, msg.as_string())
        server.quit()
    except Exception as e:
        log_action(f"Error sending email: {e}")


# Function to send email with logs
def send_email_with_logs(log_file, log_type):
    subject = f"Security Script Logs - {log_type}"
    body = read_log_file(log_file)
    send_email(subject, body)


# Function to get IP of own machine
def get_my_ip():
    """Get the current IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't have to be reachable
        s.connect(("10.255.255.255", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP


# Function to handle captured packets
def handle_packet(packet):
    global blocked_ips
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        # Get the source IP address of the packet
        src_ip = packet[IP].src
        # Ignore packets from your own machine
        if src_ip == get_my_ip():
            return

        # Check if the packet is an ICMP echo request (ping)
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            # Get the source IP address of the packet
            src_ip = packet[IP].src

            # Log the ping attempt
            log_action(f"Detected ping from {src_ip}")

            # Block incoming traffic from the attacker's IP address
            modify_ip_traffic(src_ip, "block")
            blocked_ips.add(src_ip)

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
                log_action(f"Detected port scan from {src_ip} on port {dst_port}")

                # Block incoming traffic from the attacker's IP address on the scanned port
                modify_ip_traffic(src_ip, "block")
                blocked_ips.add(src_ip)

        # Check if the packet is an SSH login attempt (indicating a brute-force login attempt)
        elif packet.haslayer(TCP) and packet[TCP].dport == 22 and packet.haslayer(Raw):
            # Get the source IP address of the packet
            src_ip = packet[IP].src

            # Increment the brute-force login counter for the source IP address
            brute_force_counter[src_ip] += 1

            # Check if the brute-force login counter has reached the threshold for detecting a brute-force login attempt
            if brute_force_counter[src_ip] >= brute_force_threshold:
                # Log the brute-force login attempt
                log_action(f"Detected brute-force login attempt from {src_ip}")

                # Block incoming traffic from the attacker's IP address
                modify_ip_traffic(src_ip, "block")
                blocked_ips.add(src_ip)


# Function to modify the IP traffic
def modify_ip_traffic(ip_address, action):
    try:
        current_platform = platform.system()
        if current_platform == "Linux":
            command = (
                f"iptables -A INPUT -s {ip_address} -j DROP"
                if action == "block"
                else f"iptables -D INPUT -s {ip_address} -j DROP"
            )
        elif current_platform == "Windows":
            command = (
                f"netsh advfirewall firewall add rule name='BlockIP_{ip_address}' dir=in interface=any action=block remoteip={ip_address}"
                if action == "block"
                else f"netsh advfirewall firewall delete rule name='BlockIP_{ip_address}'"
            )

        subprocess.run(command, shell=True, check=True)

    except Exception as e:
        print(f"Error modifying IP traffic: {e}")


# Function to capture packets
def packet_capture(action):
    """Capture packets and block or unblock IP addresses based on the action."""
    global blocked_ips
    if action == "block":
        # Start packet capture in a loop
        sniff(prn=handle_packet, stop_filter=lambda p: not security_script_running)
    elif action == "unblock":
        # Unblock all blocked IP addresses
        for ip in blocked_ips:
            modify_ip_traffic(ip, "unblock")
        blocked_ips.clear()


# Function to log an action
def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}\n"
    with open(log_file, "a") as log:
        log.write(log_message)


# Function to capture screenshot
def capture_screenshot():
    # Define the directory where you want to save the screenshots
    screenshot_dir = pathlib.Path("captured")
    # Check if the directory exists, and if not, create it
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    screenshot_file = screenshot_dir / f"screenshot_{timestamp}.png"
    with mss() as sct:
        sct.shot(output=str(screenshot_file))
    log_action(f"Captured screenshot: {screenshot_file}")


# Function to start the security script
def start_security_script():
    global security_script_running
    if security_script_running:
        print("The security script is already running.")
    else:
        security_script_running = True
        log_action("Security script started.")
        # while security_script_running:
        # Start packet capture in a new thread
        modify_website_access("block", blacklist)
        threading.Thread(target=packet_capture, args=("block",)).start()
        # send_email_with_logs(log_file, "Security Logs")
        capture_screenshot()
        time.sleep(5)


# Function to stop the security script
def stop_security_script():
    global security_script_running
    if not security_script_running:
        print("The security script is not running.")
    else:
        # Unblock all blocked IP addresses
        for ip in blocked_ips:
            modify_ip_traffic(ip, "unblock")
        blocked_ips.clear()
        modify_website_access("unblock", blacklist)
        security_script_running = False
        log_action("Security script stopped.")


# Function to load and save lists from a file
def load_save_lists(file, list=None, mode="r"):
    if mode == "r" and os.path.exists(file):
        with open(file, "r") as f:
            for line in f:
                list.add(line.strip())
    elif mode == "w":
        with open(file, "w") as f:
            for item in list:
                f.write(item + "\n")


# Function to display the blacklist
def display_blacklist():
    load_save_lists(blacklist_file, blacklist)
    print("Website Blacklist:\n" + "\n".join(blacklist))


# Function to add or remove website from blacklist
def modify_blacklist(website, action):
    if action == "add":
        blacklist.add(website)
        log_action(f"Added {website} to the website blacklist.")
    elif action == "remove" and website in blacklist:
        blacklist.remove(website)
        log_action(f"Removed {website} from the website blacklist.")
    load_save_lists(blacklist_file, blacklist, "w")


# Function to block or unblock websites from the blacklist
def modify_website_access(mode, websites):
    hosts_path = (
        r"C:\Windows\System32\drivers\etc\hosts"
        if platform.system() == "Windows"
        else "/etc/hosts"
    )

    try:
        with open(hosts_path, "r+") as file:
            lines = file.readlines()
            file.seek(0)
            file.truncate()

            if mode == "block":
                for line in lines:
                    if not any(website in line for website in websites):
                        file.write(line)
                for website in websites:
                    file.write("127.0.0.1 " + website + "\n")
            elif mode == "unblock":
                for line in lines:
                    if not any(website in line for website in websites):
                        file.write(line)

        # Flush DNS cache
        if platform.system() == "Windows":
            subprocess.call(["ipconfig", "/flushdns"])
        else:
            # For Kali Linux
            subprocess.call(["sudo", "systemd-resolve", "--flush-caches"])

        log_action(f"Successfully {mode}ed websites: {', '.join(websites)}")

    except Exception as e:
        log_action(str(e))


# Function to read log file content
def read_log_file(log_path):
    try:
        with open(log_path, "r") as log_file:
            return log_file.read()
    except Exception as e:
        return f"Error reading log file: {e}"


# Function to display a log file
def display_log_file(log_path):
    try:
        with open(log_path, "r") as log_file:
            log_content = log_file.read()
            print(log_content)
    except Exception as e:
        print(f"Error reading log file: {e}")


# Function to clear terminal
def clear_terminal():
    os.system(clear_command)
    pass


# Main menu loop
if __name__ == "__main__":
    security_script_running = False
    menu_options = {
        "1": start_security_script,
        "2": stop_security_script,
        "3": lambda: display_log_file(log_file),
        "4": display_blacklist,
        "5": lambda: modify_blacklist(
            input("Enter the website to add to the blacklist: "), "add"
        ),
        "6": lambda: modify_blacklist(
            input("Enter the website to remove from the blacklist: "), "remove"
        ),
        "7": clear_terminal,
    }

    while True:
        print("\n\nSecurity Script Menu:")
        print("1. Start the security script")
        print("2. Stop the security script")
        print("3. Display Logs")
        print("4. Display Blacklist")
        print("5. Add website to blacklist")
        print("6. Remove website from blacklist")
        print("7. Clear Screen")
        print("8. Exit")
        choice = input("Enter your choice: ")
        if choice in menu_options:
            menu_options[choice]()
        elif choice == "8":
            break
        else:
            print("Invalid choice. Please select a valid option.")

4