import numpy as np
from collections import defaultdict, Counter
import time

class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'packet_count',
            'avg_packet_size',
            'std_packet_size',
            'min_packet_size',
            'max_packet_size',
            'tcp_count',
            'udp_count',
            'icmp_count',
            'unique_src_ips',
            'unique_dst_ips',
            'unique_src_ports',
            'unique_dst_ports',
            'port_scan_score',
            'ddos_score',
            'data_exfiltration_score',
            'botnet_score'
        ]
    
    def extract_features(self, packets):
        """Extract features from a list of packets"""
        if not packets or len(packets) < 3:  # Reduced minimum from 10 to 3
            return None
        
        try:
            features = []
            
            # Basic packet statistics
            packet_sizes = [p.get('packet_size', 0) for p in packets]
            features.extend([
                len(packets),  # packet_count
                np.mean(packet_sizes),  # avg_packet_size
                np.std(packet_sizes) if len(packet_sizes) > 1 else 0,  # std_packet_size
                min(packet_sizes),  # min_packet_size
                max(packet_sizes)  # max_packet_size
            ])
            
            # Protocol counts
            protocols = [p.get('protocol', 'Unknown') for p in packets]
            protocol_counts = Counter(protocols)
            features.extend([
                protocol_counts.get('TCP', 0),  # tcp_count
                protocol_counts.get('UDP', 0),  # udp_count
                protocol_counts.get('ICMP', 0)  # icmp_count
            ])
            
            # IP and port statistics
            src_ips = [p.get('src_ip', 'Unknown') for p in packets if p.get('src_ip') != 'Unknown']
            dst_ips = [p.get('dst_ip', 'Unknown') for p in packets if p.get('dst_ip') != 'Unknown']
            src_ports = [p.get('src_port') for p in packets if p.get('src_port') is not None]
            dst_ports = [p.get('dst_port') for p in packets if p.get('dst_port') is not None]
            
            features.extend([
                len(set(src_ips)),  # unique_src_ips
                len(set(dst_ips)),  # unique_dst_ips
                len(set(src_ports)),  # unique_src_ports
                len(set(dst_ports))  # unique_dst_ports
            ])
            
            # Anomaly detection scores
            port_scan_score = self._calculate_port_scan_score(packets)
            ddos_score = self._calculate_ddos_score(packets)
            data_exfiltration_score = self._calculate_data_exfiltration_score(packets)
            botnet_score = self._calculate_botnet_score(packets)
            
            features.extend([
                port_scan_score,
                ddos_score,
                data_exfiltration_score,
                botnet_score
            ])
            
            # Convert to numpy array and handle NaN values
            features = np.array(features, dtype=np.float64)
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
            
            return features.reshape(1, -1)  # Reshape for ML model
            
        except Exception as e:
            print(f"❌ Error extracting features: {e}")
            return None
    
    def _calculate_port_scan_score(self, packets):
        """Calculate port scan detection score"""
        try:
            dst_ports = [p.get('dst_port') for p in packets if p.get('dst_port') is not None]
            if not dst_ports:
                return 0.0
            
            # Count unique ports
            unique_ports = len(set(dst_ports))
            total_packets = len(packets)
            
            # Port scan indicator: many unique ports in short time
            if unique_ports > 5 and total_packets > 10:
                # Calculate port diversity ratio
                port_diversity = unique_ports / total_packets
                if port_diversity > 0.3:  # More than 30% unique ports
                    return min(1.0, port_diversity * 2)  # Boost the score
            
            # Check for sequential port scanning
            if len(dst_ports) > 5:
                sorted_ports = sorted(dst_ports)
                sequential_count = 0
                for i in range(1, len(sorted_ports)):
                    if sorted_ports[i] == sorted_ports[i-1] + 1:
                        sequential_count += 1
                
                if sequential_count > 3:  # More than 3 sequential ports
                    return min(1.0, sequential_count / len(sorted_ports) * 2)
            
            return 0.0
            
        except Exception as e:
            return 0.0
    
    def _calculate_ddos_score(self, packets):
        """Calculate DDoS detection score"""
        try:
            if len(packets) < 5:
                return 0.0
            
            # High packet volume from few sources to one destination
            src_ips = [p.get('src_ip') for p in packets if p.get('src_ip') != 'Unknown']
            dst_ips = [p.get('dst_ip') for p in packets if p.get('dst_ip') != 'Unknown']
            
            if not src_ips or not dst_ips:
                return 0.0
            
            unique_src = len(set(src_ips))
            unique_dst = len(set(dst_ips))
            total_packets = len(packets)
            
            # DDoS pattern: many packets from few sources to few destinations
            if total_packets > 20:
                src_concentration = total_packets / max(unique_src, 1)
                dst_concentration = total_packets / max(unique_dst, 1)
                
                # High concentration on both source and destination
                if src_concentration > 5 and dst_concentration > 5:
                    return min(1.0, (src_concentration + dst_concentration) / 20)
                
                # Very high packet rate
                if total_packets > 50:
                    return min(1.0, total_packets / 100)
            
            return 0.0
            
        except Exception as e:
            return 0.0
    
    def _calculate_data_exfiltration_score(self, packets):
        """Calculate data exfiltration detection score"""
        try:
            if len(packets) < 3:
                return 0.0
            
            # Large packets going to external destinations
            packet_sizes = [p.get('packet_size', 0) for p in packets]
            dst_ips = [p.get('dst_ip') for p in packets if p.get('dst_ip') != 'Unknown']
            
            if not packet_sizes or not dst_ips:
                return 0.0
            
            avg_packet_size = np.mean(packet_sizes)
            max_packet_size = max(packet_sizes)
            
            # Check for large data transfers
            if avg_packet_size > 1000 or max_packet_size > 1400:
                # Check if going to external IPs (not local network)
                external_ips = [ip for ip in dst_ips if not ip.startswith(('192.168.', '10.', '172.'))]
                if external_ips:
                    external_ratio = len(external_ips) / len(dst_ips)
                    if external_ratio > 0.5:  # More than 50% to external IPs
                        return min(1.0, external_ratio * avg_packet_size / 2000)
            
            return 0.0
            
        except Exception as e:
            return 0.0
    
    def _calculate_botnet_score(self, packets):
        """Calculate botnet detection score"""
        try:
            if len(packets) < 5:
                return 0.0
            
            # Botnet pattern: many sources communicating with many destinations
            src_ips = [p.get('src_ip') for p in packets if p.get('src_ip') != 'Unknown']
            dst_ips = [p.get('dst_ip') for p in packets if p.get('dst_ip') != 'Unknown']
            
            if not src_ips or not dst_ips:
                return 0.0
            
            unique_src = len(set(src_ips))
            unique_dst = len(set(dst_ips))
            total_packets = len(packets)
            
            # Botnet indicators
            if unique_src > 3 and unique_dst > 3:
                # Many-to-many communication pattern
                connectivity_score = (unique_src * unique_dst) / total_packets
                if connectivity_score > 2:  # High connectivity
                    return min(1.0, connectivity_score / 10)
                
                # Check for regular communication patterns
                if total_packets > 10:
                    # Calculate packet distribution
                    src_counts = Counter(src_ips)
                    dst_counts = Counter(dst_ips)
                    
                    # Even distribution suggests botnet
                    src_std = np.std(list(src_counts.values()))
                    dst_std = np.std(list(dst_counts.values()))
                    
                    if src_std < 2 and dst_std < 2:  # Even distribution
                        return min(1.0, 0.5 + (total_packets / 50))
            
            return 0.0
            
        except Exception as e:
            return 0.0
    
    def get_feature_names(self):
        """Get list of feature names"""
        return self.feature_names.copy() 