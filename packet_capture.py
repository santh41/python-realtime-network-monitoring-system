from scapy.all import *
import threading
import time
import datetime
from collections import defaultdict, deque
import queue
import signal
import sys

class PacketCapture:
    def __init__(self, callback=None, feature_extractor=None, ml_model=None):
        self.callback = callback
        self.feature_extractor = feature_extractor
        self.ml_model = ml_model
        self.is_capturing = False
        self.capture_thread = None
        self.analysis_thread = None
        
        # Statistics
        self.packets_captured = 0
        self.anomalies_detected = 0
        self.start_time = None
        
        # Packet buffer for feature extraction (optimized size)
        self.packet_buffer = deque(maxlen=50)  # Reduced from 100 to 50
        self.packet_queue = queue.Queue(maxsize=100)  # Thread-safe queue
        
        # Time window for analysis (3 seconds - reduced from 5)
        self.time_window = 3
        self.last_analysis_time = time.time()
        
        # Stats update interval (2 seconds - increased from 1)
        self.stats_update_interval = 2
        self.last_stats_update = time.time()
        
        # Performance tracking
        self.packet_counts = defaultdict(int)
        self.last_cleanup_time = time.time()
        
        # Error tracking
        self.error_count = 0
        self.max_errors = 10
        
        # Signal handling for graceful shutdown (only in main thread)
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except ValueError:
            # Signal handling only works in main thread
            pass
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\n🛑 Received signal {signum}, shutting down gracefully...")
        self.stop_capture()
        # Only exit if we're in the main thread
        if threading.current_thread() is threading.main_thread():
            sys.exit(0)
    
    def start_capture(self):
        """Start packet capture in separate threads"""
        if self.is_capturing:
            print("⚠️ Capture already running")
            return
        
        self.is_capturing = True
        self.start_time = time.time()
        self.error_count = 0
        print("🔍 Starting packet capture...")
        
        # Start capture thread with timeout
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()
        
        print("✅ Packet capture started successfully")
    
    def stop_capture(self):
        """Stop packet capture gracefully"""
        if not self.is_capturing:
            return
        
        print("⏹️ Stopping packet capture...")
        self.is_capturing = False
        
        # Wait for threads to finish with timeout
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=2)
        
        # Clear queues
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break
        
        self.packet_buffer.clear()
        print("✅ Packet capture stopped")
    
    def _capture_packets(self):
        """Main packet capture loop with non-blocking approach"""
        try:
            # Use AsyncSniffer for non-blocking capture
            sniffer = AsyncSniffer(
                prn=self._process_packet,
                store=0,
                stop_filter=lambda p: not self.is_capturing
            )
            
            sniffer.start()
            
            # Keep the thread alive while capturing
            while self.is_capturing:
                time.sleep(0.1)  # Small sleep to prevent CPU hogging
                
                # Check for too many errors
                if self.error_count > self.max_errors:
                    print(f"❌ Too many errors ({self.error_count}), stopping capture")
                    break
            
            sniffer.stop()
            
        except Exception as e:
            print(f"❌ Error in packet capture: {e}")
            self.error_count += 1
        finally:
            self.is_capturing = False
    
    def _analysis_loop(self):
        """Separate thread for packet analysis"""
        while self.is_capturing:
            try:
                # Process packets from queue
                while not self.packet_queue.empty() and self.is_capturing:
                    try:
                        packet_data = self.packet_queue.get_nowait()
                        self.packet_buffer.append(packet_data)
                    except queue.Empty:
                        break
                
                # Analyze packets periodically
                current_time = time.time()
                if current_time - self.last_analysis_time >= self.time_window:
                    self._analyze_packet_window()
                    self.last_analysis_time = current_time
                
                # Send stats updates
                if current_time - self.last_stats_update >= self.stats_update_interval:
                    self._send_stats_update()
                    self.last_stats_update = current_time
                
                # Cleanup old data periodically
                if current_time - self.last_cleanup_time >= 30:  # Every 30 seconds
                    self._cleanup_old_data()
                    self.last_cleanup_time = current_time
                
                time.sleep(0.5)  # Reduced sleep time for more responsive updates
                
            except Exception as e:
                print(f"❌ Error in analysis loop: {e}")
                self.error_count += 1
                time.sleep(1)
    
    def _process_packet(self, packet):
        """Process each captured packet (non-blocking)"""
        if not self.is_capturing:
            return
        
        try:
            # Extract basic packet information
            packet_data = self._extract_packet_info(packet)
            
            # Add to queue (non-blocking)
            try:
                self.packet_queue.put_nowait(packet_data)
            except queue.Full:
                # Queue is full, skip this packet
                pass
            
            # Update statistics
            self.packets_captured += 1
            self.packet_counts[int(time.time())] += 1
            
        except Exception as e:
            print(f"❌ Error processing packet: {e}")
            self.error_count += 1
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from packet with better error handling"""
        packet_data = {
            'timestamp': time.time(),
            'packet_size': len(packet),
            'protocol': 'Unknown',
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown',
            'src_port': None,
            'dst_port': None
        }
        
        try:
            # Extract IP layer information
            if IP in packet:
                packet_data['src_ip'] = packet[IP].src
                packet_data['dst_ip'] = packet[IP].dst
                
                # Get protocol number and convert to name
                proto_num = packet[IP].proto
                if proto_num == 6:
                    packet_data['protocol'] = 'TCP'
                elif proto_num == 17:
                    packet_data['protocol'] = 'UDP'
                elif proto_num == 1:
                    packet_data['protocol'] = 'ICMP'
                else:
                    packet_data['protocol'] = f'Protocol_{proto_num}'
            
            # Extract TCP/UDP layer information
            if TCP in packet:
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                packet_data['protocol'] = 'TCP'
            elif UDP in packet:
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
                packet_data['protocol'] = 'UDP'
            elif ICMP in packet:
                packet_data['protocol'] = 'ICMP'
            
            # Additional protocol detection for common protocols
            if packet_data['protocol'] == 'TCP' and packet_data['dst_port']:
                if packet_data['dst_port'] == 80:
                    packet_data['protocol'] = 'HTTP'
                elif packet_data['dst_port'] == 443:
                    packet_data['protocol'] = 'HTTPS'
                elif packet_data['dst_port'] == 22:
                    packet_data['protocol'] = 'SSH'
                elif packet_data['dst_port'] == 53:
                    packet_data['protocol'] = 'DNS'
            
            # Ensure we have valid IP addresses
            if packet_data['src_ip'] == 'Unknown' and hasattr(packet, 'src'):
                packet_data['src_ip'] = packet.src
            if packet_data['dst_ip'] == 'Unknown' and hasattr(packet, 'dst'):
                packet_data['dst_ip'] = packet.dst
            
        except Exception as e:
            # Log the error but don't print every time to avoid spam
            if hasattr(self, '_last_error_log') and time.time() - self._last_error_log > 10:
                print(f"⚠️ Packet extraction error: {e}")
                self._last_error_log = time.time()
            elif not hasattr(self, '_last_error_log'):
                self._last_error_log = time.time()
        
        return packet_data
    
    def _analyze_packet_window(self):
        """Analyze packets in the current time window with error handling"""
        if not self.packet_buffer or len(self.packet_buffer) < 5:  # Minimum packets for analysis
            return
        
        try:
            # Convert buffer to list for analysis
            packets = list(self.packet_buffer)
            
            # Extract features
            if self.feature_extractor:
                features = self.feature_extractor.extract_features(packets)
                
                if features is not None and self.ml_model:
                    # Make prediction
                    prediction, confidence = self.ml_model.predict(features)
                    
                    # Call callback with results
                    if self.callback and len(packets) > 0:
                        # Use the most recent packet for display
                        latest_packet = packets[-1]
                        self.callback(latest_packet, prediction, confidence)
                        
                        if prediction != 0:  # Not normal
                            self.anomalies_detected += 1
                            print(f"🚨 Anomaly detected: {prediction} (confidence: {confidence:.2f})")
        
        except Exception as e:
            print(f"❌ Error in packet analysis: {e}")
            self.error_count += 1
    
    def _send_stats_update(self):
        """Send periodic stats update via callback"""
        if self.callback:
            try:
                # Create a dummy packet data for stats update
                stats_packet = {
                    'timestamp': time.time(),
                    'packet_size': 0,
                    'protocol': 'STATS_UPDATE',
                    'src_ip': 'N/A',
                    'dst_ip': 'N/A'
                }
                # Send stats update with dummy prediction (0 = normal)
                self.callback(stats_packet, 0, 0.0)
            except Exception as e:
                print(f"❌ Error sending stats update: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old data to prevent memory issues"""
        try:
            # Clean up old packet counts (keep only last 60 seconds)
            current_time = int(time.time())
            old_timestamps = [ts for ts in self.packet_counts.keys() if current_time - ts > 60]
            for ts in old_timestamps:
                del self.packet_counts[ts]
        except Exception as e:
            print(f"❌ Error in cleanup: {e}")
    
    def get_stats(self):
        """Get current capture statistics"""
        current_time = time.time()
        duration = current_time - self.start_time if self.start_time else 0
        
        # Calculate packets per second
        packets_per_second = 0
        if duration > 0:
            packets_per_second = self.packets_captured / duration
        
        return {
            'packets_captured': self.packets_captured,
            'anomalies_detected': self.anomalies_detected,
            'packets_per_second': round(packets_per_second, 2),
            'duration_seconds': round(duration, 2),
            'is_capturing': self.is_capturing,
            'buffer_size': len(self.packet_buffer),
            'queue_size': self.packet_queue.qsize(),
            'error_count': self.error_count
        }
    
    def get_packet_counts(self):
        """Get packet counts for the last minute"""
        current_time = int(time.time())
        counts = {}
        
        for i in range(60):  # Last 60 seconds
            timestamp = current_time - i
            counts[timestamp] = self.packet_counts.get(timestamp, 0)
        
        return counts 