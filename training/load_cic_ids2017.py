import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings('ignore')

class CICIDS2017Loader:
    """Loader for CIC-IDS2017 dataset"""
    
    def __init__(self, data_dir='data/cic-ids2017'):
        self.data_dir = data_dir
        self.label_encoder = LabelEncoder()
        
        # CIC-IDS2017 attack mappings
        self.attack_mapping = {
            'BENIGN': 0,
            'DoS slowloris': 1,  # DDoS
            'DoS Slowhttptest': 1,  # DDoS
            'DoS Hulk': 1,  # DDoS
            'DoS GoldenEye': 1,  # DDoS
            'PortScan': 2,  # Port Scan
            'Bot': 3,  # Botnet
            'Infiltration': 4,  # Data Exfiltration
            'Web Attack – Brute Force': 4,  # Data Exfiltration
            'Web Attack – XSS': 4,  # Data Exfiltration
            'Web Attack – SQL Injection': 4,  # Data Exfiltration
            'Heartbleed': 4  # Data Exfiltration
        }
        
        # Feature mapping from CIC-IDS2017 to our schema
        self.feature_mapping = {
            # Basic packet statistics
            'Total Length of Fwd Packets': 'avg_packet_size',
            'Total Length of Bwd Packets': 'max_packet_size',
            'Fwd Packet Length Max': 'max_packet_size',
            'Fwd Packet Length Min': 'min_packet_size',
            'Fwd Packet Length Std': 'std_packet_size',
            
            # Protocol counts (derived)
            'Protocol': 'protocol',
            
            # IP and port statistics
            'Total Fwd Packets': 'packet_count',
            'Total Backward Packets': 'packet_count',
            'Fwd IAT Total': 'packet_count',
            'Bwd IAT Total': 'packet_count',
            
            # Anomaly indicators
            'Flow Duration': 'ddos_score',
            'Flow Bytes/s': 'ddos_score',
            'Flow Packets/s': 'ddos_score',
            'Flow IAT Mean': 'port_scan_score',
            'Flow IAT Std': 'port_scan_score',
            'Flow IAT Max': 'port_scan_score',
            'Flow IAT Min': 'port_scan_score',
            'Fwd IAT Mean': 'botnet_score',
            'Fwd IAT Std': 'botnet_score',
            'Fwd IAT Max': 'botnet_score',
            'Fwd IAT Min': 'botnet_score',
            'Bwd IAT Mean': 'data_exfiltration_score',
            'Bwd IAT Std': 'data_exfiltration_score',
            'Bwd IAT Max': 'data_exfiltration_score',
            'Bwd IAT Min': 'data_exfiltration_score'
        }
    
    def load_data(self, file_path=None):
        """Load CIC-IDS2017 data and map to our feature schema"""
        try:
            if file_path is None:
                # Try to find CIC-IDS2017 files in data directory
                if not os.path.exists(self.data_dir):
                    print(f"⚠️ CIC-IDS2017 data directory not found: {self.data_dir}")
                    print("📥 Please download CIC-IDS2017 dataset and place in data/cic-ids2017/")
                    return None, None
                
                # Look for CSV files
                csv_files = [f for f in os.listdir(self.data_dir) if f.endswith('.csv')]
                if not csv_files:
                    print(f"⚠️ No CSV files found in {self.data_dir}")
                    return None, None
                
                # Use the first CSV file found
                file_path = os.path.join(self.data_dir, csv_files[0])
            
            print(f"📂 Loading CIC-IDS2017 data from: {file_path}")
            
            # Load data
            df = pd.read_csv(file_path, low_memory=False)
            print(f"📊 Loaded {len(df)} samples with {len(df.columns)} features")
            
            # Clean and preprocess
            X, y = self._preprocess_data(df)
            
            return X, y
            
        except Exception as e:
            print(f"❌ Error loading CIC-IDS2017 data: {e}")
            return None, None
    
    def _preprocess_data(self, df):
        """Preprocess the loaded data"""
        try:
            # Remove rows with missing values
            df = df.dropna()
            
            # Extract labels
            if 'Label' in df.columns:
                labels = df['Label'].values
            elif 'label' in df.columns:
                labels = df['label'].values
            else:
                print("❌ No label column found in dataset")
                return None, None
            
            # Map labels to our schema
            y = np.array([self.attack_mapping.get(label, 0) for label in labels])
            
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
        """Extract features from CIC-IDS2017 data"""
        try:
            features = []
            
            # Basic packet statistics
            features.append(df.get('Total Fwd Packets', 0).fillna(0).values)  # packet_count
            features.append(df.get('Total Length of Fwd Packets', 0).fillna(0).values)  # avg_packet_size
            features.append(df.get('Fwd Packet Length Std', 0).fillna(0).values)  # std_packet_size
            features.append(df.get('Fwd Packet Length Min', 0).fillna(0).values)  # min_packet_size
            features.append(df.get('Fwd Packet Length Max', 0).fillna(0).values)  # max_packet_size
            
            # Protocol counts (simplified - assume TCP for most flows)
            features.append(df.get('Total Fwd Packets', 0).fillna(0).values * 0.8)  # tcp_count
            features.append(df.get('Total Fwd Packets', 0).fillna(0).values * 0.15)  # udp_count
            features.append(df.get('Total Fwd Packets', 0).fillna(0).values * 0.05)  # icmp_count
            
            # IP and port statistics (simplified)
            features.append(df.get('Total Fwd Packets', 0).fillna(0).values * 0.1)  # unique_src_ips
            features.append(df.get('Total Backward Packets', 0).fillna(0).values * 0.1)  # unique_dst_ips
            features.append(df.get('Total Fwd Packets', 0).fillna(0).values * 0.2)  # unique_src_ports
            features.append(df.get('Total Backward Packets', 0).fillna(0).values * 0.2)  # unique_dst_ports
            
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
        """Calculate port scan score from CIC-IDS2017 features"""
        try:
            # Use flow statistics as indicators
            flow_duration = df.get('Flow Duration', 0).fillna(0).values
            flow_packets = df.get('Flow Packets/s', 0).fillna(0).values
            
            # Normalize and combine
            score = np.zeros(len(df))
            if len(flow_duration) > 0:
                score += (flow_duration / np.max(flow_duration)) * 0.5
            if len(flow_packets) > 0:
                score += (flow_packets / np.max(flow_packets)) * 0.5
            
            return np.clip(score, 0, 1)
        except:
            return np.zeros(len(df))
    
    def _calculate_ddos_score(self, df):
        """Calculate DDoS score from CIC-IDS2017 features"""
        try:
            # Use flow bytes per second as indicator
            flow_bytes = df.get('Flow Bytes/s', 0).fillna(0).values
            
            # Normalize
            score = np.zeros(len(df))
            if len(flow_bytes) > 0:
                score = flow_bytes / np.max(flow_bytes)
            
            return np.clip(score, 0, 1)
        except:
            return np.zeros(len(df))
    
    def _calculate_data_exfiltration_score(self, df):
        """Calculate data exfiltration score from CIC-IDS2017 features"""
        try:
            # Use backward packet length as indicator
            bwd_length = df.get('Total Length of Bwd Packets', 0).fillna(0).values
            
            # Normalize
            score = np.zeros(len(df))
            if len(bwd_length) > 0:
                score = bwd_length / np.max(bwd_length)
            
            return np.clip(score, 0, 1)
        except:
            return np.zeros(len(df))
    
    def _calculate_botnet_score(self, df):
        """Calculate botnet score from CIC-IDS2017 features"""
        try:
            # Use flow IAT statistics as indicators
            flow_iat_mean = df.get('Flow IAT Mean', 0).fillna(0).values
            flow_iat_std = df.get('Flow IAT Std', 0).fillna(0).values
            
            # Normalize and combine
            score = np.zeros(len(df))
            if len(flow_iat_mean) > 0:
                score += (flow_iat_mean / np.max(flow_iat_mean)) * 0.5
            if len(flow_iat_std) > 0:
                score += (flow_iat_std / np.max(flow_iat_std)) * 0.5
            
            return np.clip(score, 0, 1)
        except:
            return np.zeros(len(df))

def main():
    """Test the CIC-IDS2017 loader"""
    loader = CICIDS2017Loader()
    X, y = loader.load_data()
    
    if X is not None and y is not None:
        print(f"✅ Successfully loaded CIC-IDS2017 data")
        print(f"📊 Features shape: {X.shape}")
        print(f"📊 Labels shape: {y.shape}")
        print(f"📊 Label distribution: {np.bincount(y)}")
    else:
        print("❌ Failed to load CIC-IDS2017 data")

if __name__ == "__main__":
    main()
