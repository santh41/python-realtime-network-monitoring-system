import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings('ignore')

class UNSWNB15Loader:
    """Loader for UNSW-NB15 dataset"""
    
    def __init__(self, data_dir='data/unsw-nb15'):
        self.data_dir = data_dir
        self.label_encoder = LabelEncoder()
        
        # UNSW-NB15 attack mappings
        self.attack_mapping = {
            'normal': 0,
            'dos': 1,  # DDoS
            'probe': 2,  # Port Scan
            'r2l': 4,  # Data Exfiltration
            'u2r': 4,  # Data Exfiltration
            'backdoor': 3,  # Botnet
            'worms': 3,  # Botnet
            'analysis': 2,  # Port Scan
            'fuzzers': 2,  # Port Scan
            'shellcode': 4,  # Data Exfiltration
            'generic': 1,  # DDoS
            'exploits': 4  # Data Exfiltration
        }
        
        # Feature mapping from UNSW-NB15 to our schema
        self.feature_mapping = {
            # Basic packet statistics
            'dur': 'packet_count',  # Duration as proxy for packet count
            'sbytes': 'avg_packet_size',  # Source bytes
            'dbytes': 'max_packet_size',  # Destination bytes
            'sttl': 'std_packet_size',  # Source TTL
            'dttl': 'min_packet_size',  # Destination TTL
            
            # Protocol counts
            'proto': 'protocol',
            'service': 'protocol',
            'state': 'protocol',
            
            # IP and port statistics
            'srcip': 'unique_src_ips',
            'dstip': 'unique_dst_ips',
            'sport': 'unique_src_ports',
            'dport': 'unique_dst_ports',
            
            # Anomaly indicators
            'sloss': 'ddos_score',  # Source packets lost
            'dloss': 'ddos_score',  # Destination packets lost
            'sinpkt': 'port_scan_score',  # Source inter-packet arrival time
            'dinpkt': 'port_scan_score',  # Destination inter-packet arrival time
            'sjit': 'botnet_score',  # Source jitter
            'djit': 'botnet_score',  # Destination jitter
            'swin': 'data_exfiltration_score',  # Source TCP window
            'dwin': 'data_exfiltration_score',  # Destination TCP window
            'stcpb': 'data_exfiltration_score',  # Source TCP base sequence number
            'dtcpb': 'data_exfiltration_score',  # Destination TCP base sequence number
            'smeansz': 'data_exfiltration_score',  # Source mean packet size
            'dmeansz': 'data_exfiltration_score',  # Destination mean packet size
            'trans_depth': 'port_scan_score',  # Transaction depth
            'response_body_len': 'data_exfiltration_score',  # Response body length
            'ct_srv_src': 'botnet_score',  # Count of connections from same service to same source
            'ct_srv_dst': 'botnet_score',  # Count of connections from same service to same destination
            'ct_dst_ltm': 'ddos_score',  # Count of connections to same destination
            'ct_src_ltm': 'ddos_score',  # Count of connections from same source
            'ct_src_dport_ltm': 'port_scan_score',  # Count of connections from same source to same destination port
            'ct_dst_sport_ltm': 'port_scan_score',  # Count of connections to same destination from same source port
            'ct_dst_src_ltm': 'botnet_score',  # Count of connections to same destination from same source
            'ct_ftp_cmd': 'data_exfiltration_score',  # Count of FTP commands
            'ct_flw_http_mthd': 'data_exfiltration_score',  # Count of HTTP methods
            'ct_src_ltm': 'ddos_score',  # Count of connections from same source
            'ct_srv_src': 'botnet_score',  # Count of connections from same service to same source
            'ct_srv_dst': 'botnet_score',  # Count of connections from same service to same destination
            'ct_dst_ltm': 'ddos_score',  # Count of connections to same destination
            'ct_src_dport_ltm': 'port_scan_score',  # Count of connections from same source to same destination port
            'ct_dst_sport_ltm': 'port_scan_score',  # Count of connections to same destination from same source port
            'ct_dst_src_ltm': 'botnet_score',  # Count of connections to same destination from same source
            'ct_ftp_cmd': 'data_exfiltration_score',  # Count of FTP commands
            'ct_flw_http_mthd': 'data_exfiltration_score',  # Count of HTTP methods
            'ct_src_ltm': 'ddos_score',  # Count of connections from same source
            'ct_srv_src': 'botnet_score',  # Count of connections from same service to same source
            'ct_srv_dst': 'botnet_score',  # Count of connections from same service to same destination
            'ct_dst_ltm': 'ddos_score',  # Count of connections to same destination
            'ct_src_dport_ltm': 'port_scan_score',  # Count of connections from same source to same destination port
            'ct_dst_sport_ltm': 'port_scan_score',  # Count of connections to same destination from same source port
            'ct_dst_src_ltm': 'botnet_score',  # Count of connections to same destination from same source
            'ct_ftp_cmd': 'data_exfiltration_score',  # Count of FTP commands
            'ct_flw_http_mthd': 'data_exfiltration_score'  # Count of HTTP methods
        }
    
    def load_data(self, file_path=None):
        """Load UNSW-NB15 data and map to our feature schema"""
        try:
            if file_path is None:
                # Try to find UNSW-NB15 files in data directory
                if not os.path.exists(self.data_dir):
                    print(f"⚠️ UNSW-NB15 data directory not found: {self.data_dir}")
                    print("📥 Please download UNSW-NB15 dataset and place in data/unsw-nb15/")
                    return None, None
                
                # Look for CSV files
                csv_files = [f for f in os.listdir(self.data_dir) if f.endswith('.csv')]
                if not csv_files:
                    print(f"⚠️ No CSV files found in {self.data_dir}")
                    return None, None
                
                # Use the first CSV file found
                file_path = os.path.join(self.data_dir, csv_files[0])
            
            print(f"📂 Loading UNSW-NB15 data from: {file_path}")
            
            # Load data
            df = pd.read_csv(file_path, low_memory=False)
            print(f"📊 Loaded {len(df)} samples with {len(df.columns)} features")
            
            # Clean and preprocess
            X, y = self._preprocess_data(df)
            
            return X, y
            
        except Exception as e:
            print(f"❌ Error loading UNSW-NB15 data: {e}")
            return None, None
    
    def _preprocess_data(self, df):
        """Preprocess the loaded data"""
        try:
            # Remove rows with missing values
            df = df.dropna()
            
            # Extract labels
            if 'label' in df.columns:
                labels = df['label'].values
            elif 'Label' in df.columns:
                labels = df['Label'].values
            else:
                print("❌ No label column found in dataset")
                return None, None
            
            # Map labels to our schema
            y = np.array([self.attack_mapping.get(label.lower(), 0) for label in labels])
            
            # Extract features
            X = self._extract_features(df)
            
            # Remove samples with invalid features
            valid_mask = ~np.isnan(X).any(axis=1) & ~np.isinf(X).any(axis=1)
            X = X[valid_mask]
            y = y[valid_mask]
            
            print(f"✅ Preprocessed data: {len(X)} samples, {X.shape[1]} features")
            print(f"📊 Label distribution: {np.bincount(y)}")
            
            return X, y
            
        except Exception as e:
            print(f"❌ Error preprocessing data: {e}")
            return None, None
    
    def _extract_features(self, df):
        """Extract features from UNSW-NB15 data"""
        try:
            features = []
            
            # Basic packet statistics
            features.append(df.get('dur', 0).fillna(0).values)  # packet_count (duration as proxy)
            features.append(df.get('sbytes', 0).fillna(0).values)  # avg_packet_size
            features.append(df.get('sttl', 0).fillna(0).values)  # std_packet_size
            features.append(df.get('dttl', 0).fillna(0).values)  # min_packet_size
            features.append(df.get('dbytes', 0).fillna(0).values)  # max_packet_size
            
            # Protocol counts (simplified)
            features.append(df.get('dur', 0).fillna(0).values * 0.8)  # tcp_count
            features.append(df.get('dur', 0).fillna(0).values * 0.15)  # udp_count
            features.append(df.get('dur', 0).fillna(0).values * 0.05)  # icmp_count
            
            # IP and port statistics (simplified)
            features.append(df.get('dur', 0).fillna(0).values * 0.1)  # unique_src_ips
            features.append(df.get('dur', 0).fillna(0).values * 0.1)  # unique_dst_ips
            features.append(df.get('dur', 0).fillna(0).values * 0.2)  # unique_src_ports
            features.append(df.get('dur', 0).fillna(0).values * 0.2)  # unique_dst_ports
            
            # Anomaly detection scores
            features.append(self._calculate_port_scan_score(df))  # port_scan_score
            features.append(self._calculate_ddos_score(df))  # ddos_score
            features.append(self._calculate_data_exfiltration_score(df))  # data_exfiltration_score
            features.append(self._calculate_botnet_score(df))  # botnet_score
            
            # Convert to numpy array
            X = np.column_stack(features)
            
            # Handle infinite values
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            return X
            
        except Exception as e:
            print(f"❌ Error extracting features: {e}")
            return None
    
    def _calculate_port_scan_score(self, df):
        """Calculate port scan score from UNSW-NB15 features"""
        try:
            # Use connection statistics as indicators
            sinpkt = df.get('sinpkt', 0).fillna(0).values
            dinpkt = df.get('dinpkt', 0).fillna(0).values
            trans_depth = df.get('trans_depth', 0).fillna(0).values
            
            # Normalize and combine
            score = np.zeros(len(df))
            if len(sinpkt) > 0:
                score += (sinpkt / np.max(sinpkt)) * 0.3
            if len(dinpkt) > 0:
                score += (dinpkt / np.max(dinpkt)) * 0.3
            if len(trans_depth) > 0:
                score += (trans_depth / np.max(trans_depth)) * 0.4
            
            return np.clip(score, 0, 1)
        except:
            return np.zeros(len(df))
    
    def _calculate_ddos_score(self, df):
        """Calculate DDoS score from UNSW-NB15 features"""
        try:
            # Use packet loss and connection counts as indicators
            sloss = df.get('sloss', 0).fillna(0).values
            dloss = df.get('dloss', 0).fillna(0).values
            ct_dst_ltm = df.get('ct_dst_ltm', 0).fillna(0).values
            ct_src_ltm = df.get('ct_src_ltm', 0).fillna(0).values
            
            # Normalize and combine
            score = np.zeros(len(df))
            if len(sloss) > 0:
                score += (sloss / np.max(sloss)) * 0.25
            if len(dloss) > 0:
                score += (dloss / np.max(dloss)) * 0.25
            if len(ct_dst_ltm) > 0:
                score += (ct_dst_ltm / np.max(ct_dst_ltm)) * 0.25
            if len(ct_src_ltm) > 0:
                score += (ct_src_ltm / np.max(ct_src_ltm)) * 0.25
            
            return np.clip(score, 0, 1)
        except:
            return np.zeros(len(df))
    
    def _calculate_data_exfiltration_score(self, df):
        """Calculate data exfiltration score from UNSW-NB15 features"""
        try:
            # Use packet sizes and response lengths as indicators
            smeansz = df.get('smeansz', 0).fillna(0).values
            dmeansz = df.get('dmeansz', 0).fillna(0).values
            response_body_len = df.get('response_body_len', 0).fillna(0).values
            ct_ftp_cmd = df.get('ct_ftp_cmd', 0).fillna(0).values
            
            # Normalize and combine
            score = np.zeros(len(df))
            if len(smeansz) > 0:
                score += (smeansz / np.max(smeansz)) * 0.25
            if len(dmeansz) > 0:
                score += (dmeansz / np.max(dmeansz)) * 0.25
            if len(response_body_len) > 0:
                score += (response_body_len / np.max(response_body_len)) * 0.25
            if len(ct_ftp_cmd) > 0:
                score += (ct_ftp_cmd / np.max(ct_ftp_cmd)) * 0.25
            
            return np.clip(score, 0, 1)
        except:
            return np.zeros(len(df))
    
    def _calculate_botnet_score(self, df):
        """Calculate botnet score from UNSW-NB15 features"""
        try:
            # Use jitter and connection patterns as indicators
            sjit = df.get('sjit', 0).fillna(0).values
            djit = df.get('djit', 0).fillna(0).values
            ct_srv_src = df.get('ct_srv_src', 0).fillna(0).values
            ct_srv_dst = df.get('ct_srv_dst', 0).fillna(0).values
            ct_dst_src_ltm = df.get('ct_dst_src_ltm', 0).fillna(0).values
            
            # Normalize and combine
            score = np.zeros(len(df))
            if len(sjit) > 0:
                score += (sjit / np.max(sjit)) * 0.2
            if len(djit) > 0:
                score += (djit / np.max(djit)) * 0.2
            if len(ct_srv_src) > 0:
                score += (ct_srv_src / np.max(ct_srv_src)) * 0.2
            if len(ct_srv_dst) > 0:
                score += (ct_srv_dst / np.max(ct_srv_dst)) * 0.2
            if len(ct_dst_src_ltm) > 0:
                score += (ct_dst_src_ltm / np.max(ct_dst_src_ltm)) * 0.2
            
            return np.clip(score, 0, 1)
        except:
            return np.zeros(len(df))

def main():
    """Test the UNSW-NB15 loader"""
    loader = UNSWNB15Loader()
    X, y = loader.load_data()
    
    if X is not None and y is not None:
        print(f"✅ Successfully loaded UNSW-NB15 data")
        print(f"📊 Features shape: {X.shape}")
        print(f"📊 Labels shape: {y.shape}")
        print(f"📊 Label distribution: {np.bincount(y)}")
    else:
        print("❌ Failed to load UNSW-NB15 data")

if __name__ == "__main__":
    main()
