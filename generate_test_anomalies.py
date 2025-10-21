#!/usr/bin/env python3
"""
Generate synthetic anomaly data for testing the network anomaly detection system
"""

import time
import random
import threading
from scapy.all import *
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def generate_ddos_traffic(duration=10):
    """Generate DDoS-like traffic patterns"""
    print(f"🚨 Generating DDoS traffic for {duration} seconds...")
    
    def send_ddos_packets():
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            # Generate many packets from few sources to one destination
            for i in range(50):  # Burst of 50 packets
                # Random source IPs (few sources)
                src_ip = f"192.168.{random.randint(1, 3)}.{random.randint(1, 10)}"
                dst_ip = "192.168.29.66"  # Target IP
                
                # Create packet
                packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80)
                send(packet, verbose=False)
                packet_count += 1
            
            time.sleep(0.1)  # Small delay between bursts
        
        print(f"✅ DDoS traffic generated: {packet_count} packets")
    
    # Run in separate thread
    thread = threading.Thread(target=send_ddos_packets, daemon=True)
    thread.start()
    return thread

def generate_port_scan_traffic(duration=10):
    """Generate port scan-like traffic patterns"""
    print(f"🔍 Generating port scan traffic for {duration} seconds...")
    
    def send_port_scan_packets():
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            # Generate packets to many different ports
            src_ip = f"192.168.{random.randint(1, 5)}.{random.randint(1, 20)}"
            dst_ip = "192.168.29.66"
            
            # Scan different port ranges
            for port in range(20, 100):  # Scan ports 20-99
                packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=port)
                send(packet, verbose=False)
                packet_count += 1
                
                if packet_count % 10 == 0:  # Small delay every 10 packets
                    time.sleep(0.01)
        
        print(f"✅ Port scan traffic generated: {packet_count} packets")
    
    # Run in separate thread
    thread = threading.Thread(target=send_port_scan_packets, daemon=True)
    thread.start()
    return thread

def generate_botnet_traffic(duration=10):
    """Generate botnet-like traffic patterns"""
    print(f"🤖 Generating botnet traffic for {duration} seconds...")
    
    def send_botnet_packets():
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            # Generate traffic from many sources to many destinations
            for i in range(20):  # 20 packets per iteration
                src_ip = f"192.168.{random.randint(1, 10)}.{random.randint(1, 50)}"
                dst_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 50)}"
                
                packet = IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=random.randint(1024, 65535), 
                    dport=random.choice([80, 443, 22, 53, 25])
                )
                send(packet, verbose=False)
                packet_count += 1
            
            time.sleep(0.2)  # Regular intervals
        
        print(f"✅ Botnet traffic generated: {packet_count} packets")
    
    # Run in separate thread
    thread = threading.Thread(target=send_botnet_packets, daemon=True)
    thread.start()
    return thread

def generate_data_exfiltration_traffic(duration=10):
    """Generate data exfiltration-like traffic patterns"""
    print(f"📤 Generating data exfiltration traffic for {duration} seconds...")
    
    def send_data_exfiltration_packets():
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            # Generate large packets to external destinations
            src_ip = "192.168.29.66"
            dst_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            # Create large payload
            payload = "A" * 1400  # Large payload
            
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=443) / Raw(load=payload)
            send(packet, verbose=False)
            packet_count += 1
            
            time.sleep(0.1)  # Regular intervals
        
        print(f"✅ Data exfiltration traffic generated: {packet_count} packets")
    
    # Run in separate thread
    thread = threading.Thread(target=send_data_exfiltration_packets, daemon=True)
    thread.start()
    return thread

def main():
    """Main function to generate different types of anomaly traffic"""
    print("🎯 Network Anomaly Traffic Generator")
    print("=" * 50)
    print("This script will generate synthetic anomaly traffic to test the detection system.")
    print("Make sure the anomaly detection system is running first!")
    print()
    
    # Check if running as admin (required for packet injection)
    try:
        # Try to send a test packet
        test_packet = IP(dst="127.0.0.1") / ICMP()
        send(test_packet, verbose=False)
    except Exception as e:
        print("❌ Error: This script requires administrator privileges to inject packets.")
        print("Please run as administrator/sudo.")
        return
    
    print("✅ Administrator privileges confirmed")
    print()
    
    # Menu for different anomaly types
    print("Select anomaly type to generate:")
    print("1. DDoS Attack")
    print("2. Port Scan")
    print("3. Botnet Traffic")
    print("4. Data Exfiltration")
    print("5. All Anomalies (Sequential)")
    print("6. Exit")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == "1":
                duration = int(input("Enter duration in seconds (default 10): ") or "10")
                thread = generate_ddos_traffic(duration)
                thread.join()
                
            elif choice == "2":
                duration = int(input("Enter duration in seconds (default 10): ") or "10")
                thread = generate_port_scan_traffic(duration)
                thread.join()
                
            elif choice == "3":
                duration = int(input("Enter duration in seconds (default 10): ") or "10")
                thread = generate_botnet_traffic(duration)
                thread.join()
                
            elif choice == "4":
                duration = int(input("Enter duration in seconds (default 10): ") or "10")
                thread = generate_data_exfiltration_traffic(duration)
                thread.join()
                
            elif choice == "5":
                print("🔄 Generating all anomaly types sequentially...")
                duration = int(input("Enter duration per anomaly in seconds (default 5): ") or "5")
                
                # Generate each type sequentially
                anomalies = [
                    ("DDoS", generate_ddos_traffic),
                    ("Port Scan", generate_port_scan_traffic),
                    ("Botnet", generate_botnet_traffic),
                    ("Data Exfiltration", generate_data_exfiltration_traffic)
                ]
                
                for name, generator in anomalies:
                    print(f"\n🎯 Generating {name} traffic...")
                    thread = generator(duration)
                    thread.join()
                    time.sleep(2)  # Wait between different types
                
                print("\n✅ All anomaly types generated!")
                
            elif choice == "6":
                print("👋 Exiting...")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1-6.")
                
        except KeyboardInterrupt:
            print("\n🛑 Interrupted by user")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
