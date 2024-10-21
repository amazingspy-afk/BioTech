import warnings
from scapy.all import *
from collections import defaultdict
import re
import logging

# Suppress specific CryptographyDeprecationWarning related to TripleDES in Scapy
warnings.filterwarnings("ignore", message=".*TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES.*")

# Configure logging
logging.basicConfig(filename='idps.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Dictionary to store counts for various attack types
attack_trackers = {
    "syn_flood": defaultdict(int),
    "udp_flood": defaultdict(int),
    "icmp_flood": defaultdict(int),
    "port_scan": defaultdict(set),
    "http_flood": defaultdict(int),
    "brute_force": defaultdict(int),
    "xss_attempts": defaultdict(int),
    "sql_injections": defaultdict(int),
    "malicious_file_uploads": defaultdict(int),
}

# IP Whitelist and Blacklist
ip_whitelist = set()  # Add IPs that should be allowed
ip_blacklist = set()  # Add IPs that should be blocked

# Thresholds for attack detection
SYN_FLOOD_THRESHOLD = 100
UDP_FLOOD_THRESHOLD = 100
ICMP_FLOOD_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 10
HTTP_FLOOD_THRESHOLD = 200
BRUTE_FORCE_THRESHOLD = 5
XSS_THRESHOLD = 10
SQL_INJECTION_THRESHOLD = 10
MALICIOUS_UPLOAD_THRESHOLD = 5

def log_alert(alert_message):
    logging.info(alert_message)
    print(alert_message)

def is_ip_blocked(src_ip):
    return src_ip in ip_blacklist

def detect_syn_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        attack_trackers["syn_flood"][src_ip] += 1
        
        if attack_trackers["syn_flood"][src_ip] > SYN_FLOOD_THRESHOLD:
            log_alert(f"Potential SYN flood attack detected from IP: {src_ip}")

def detect_udp_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(UDP):
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        attack_trackers["udp_flood"][src_ip] += 1
        
        if attack_trackers["udp_flood"][src_ip] > UDP_FLOOD_THRESHOLD:
            log_alert(f"Potential UDP flood attack detected from IP: {src_ip}")

def detect_icmp_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        attack_trackers["icmp_flood"][src_ip] += 1
        
        if attack_trackers["icmp_flood"][src_ip] > ICMP_FLOOD_THRESHOLD:
            log_alert(f"Potential ICMP flood attack detected from IP: {src_ip}")

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        dst_port = packet[TCP].dport
        attack_trackers["port_scan"][src_ip].add(dst_port)
        
        if len(attack_trackers["port_scan"][src_ip]) > PORT_SCAN_THRESHOLD:
            log_alert(f"Potential port scan detected from IP: {src_ip}")

def detect_http_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 80:
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        attack_trackers["http_flood"][src_ip] += 1
        
        if attack_trackers["http_flood"][src_ip] > HTTP_FLOOD_THRESHOLD:
            log_alert(f"Potential HTTP flood attack detected from IP: {src_ip}")

def detect_brute_force(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 80:
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        if b"login" in bytes(packet) and b"failed" in bytes(packet):
            attack_trackers["brute_force"][src_ip] += 1
            
            if attack_trackers["brute_force"][src_ip] > BRUTE_FORCE_THRESHOLD:
                log_alert(f"Potential brute force attack detected from IP: {src_ip}")

def detect_xss_attempt(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        if re.search(r'<script>|%3Cscript%3E', payload):
            attack_trackers["xss_attempts"][src_ip] += 1
            
            if attack_trackers["xss_attempts"][src_ip] > XSS_THRESHOLD:
                log_alert(f"Potential XSS attack detected from IP: {src_ip}")

def detect_sql_injection(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        if re.search(r"(?i)(union.*select|select.*from|;|--|%27|%3B)", payload):
            attack_trackers["sql_injections"][src_ip] += 1
            
            if attack_trackers["sql_injections"][src_ip] > SQL_INJECTION_THRESHOLD:
                log_alert(f"Potential SQL injection attack detected from IP: {src_ip}")

def detect_malicious_file_upload(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        src_ip = packet[IP].src
        if is_ip_blocked(src_ip):
            return
        if '/upload' in payload and ('.php' in payload or '.exe' in payload or 'cmd' in payload):
            attack_trackers["malicious_file_uploads"][src_ip] += 1
            
            if attack_trackers["malicious_file_uploads"][src_ip] > MALICIOUS_UPLOAD_THRESHOLD:
                log_alert(f"Potential malicious file upload detected from IP: {src_ip}")

def monitor_traffic():
    print("Starting network traffic monitoring...")
    while True:
        packet = sniff(count=1, filter="ip", store=0)
        if packet:
            packet = packet[0]
            detect_syn_flood(packet)
            detect_udp_flood(packet)
            detect_icmp_flood(packet)
            detect_port_scan(packet)
            detect_http_flood(packet)
            detect_brute_force(packet)
            detect_xss_attempt(packet)
            detect_sql_injection(packet)
            detect_malicious_file_upload(packet)

if __name__ == "__main__":
    monitor_traffic()
