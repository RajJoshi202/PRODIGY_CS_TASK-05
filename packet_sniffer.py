from scapy.all import sniff, IP, TCP, UDP, Raw
import datetime
import os  # Added this line to fix the 'os is not defined' error
import sys

# Log file for captured packets
LOG_FILE = "packets.log"

def log_packet(packet):
    """Log packet details to a file and print to console."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"\n[{timestamp}] Packet Captured:\n"
        
        # Check if packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, f"Unknown ({protocol})")
            log_entry += f"Source IP: {src_ip}\n"
            log_entry += f"Destination IP: {dst_ip}\n"
            log_entry += f"Protocol: {proto_name}\n"
            
            # Check for TCP/UDP details
            if TCP in packet:
                log_entry += f"Source Port: {packet[TCP].sport}\n"
                log_entry += f"Destination Port: {packet[TCP].dport}\n"
            elif UDP in packet:
                log_entry += f"Source Port: {packet[UDP].sport}\n"
                log_entry += f"Destination Port: {packet[UDP].dport}\n"
            
            # Extract payload if available
            if Raw in packet:
                payload = packet[Raw].load
                try:
                    # Try to decode payload as UTF-8, fallback to hex
                    payload_str = payload.decode('utf-8', errors='ignore')
                    log_entry += f"Payload: {payload_str[:100]}...\n"  # Limit to 100 chars
                except:
                    log_entry += f"Payload (hex): {payload.hex()[:100]}...\n"
        
        else:
            log_entry += "Non-IP packet\n"
        
        # Print to console and write to file
        print(log_entry)
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "-" * 50 + "\n")
            
    except Exception as e:
        error_msg = f"[{timestamp}] Error processing packet: {str(e)}\n"
        print(error_msg)
        with open(LOG_FILE, "a") as f:
            f.write(error_msg)

def main():
    """Main function to start packet sniffing."""
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    
    try:
        # Clear log file if it exists
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
        
        # Start sniffing packets
        # filter="ip" captures only IP packets; remove for all packets
        sniff(prn=log_packet, filter="ip", store=0, count=0)
        
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()