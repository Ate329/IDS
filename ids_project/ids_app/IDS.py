import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd
import numpy as np
import joblib
import logging
from datetime import datetime, timedelta
import time
import logging
from .network_feature_extractor import NetworkFeatureExtractor
from sklearn.preprocessing import StandardScaler
from collections import deque, Counter
import threading
import smtplib
import psutil
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import csv
import os 
import traceback
from .models import EmailSettings
from django.core.exceptions import ObjectDoesNotExist

# Absolute paths for important files
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODELS_DIR = os.path.join(PROJECT_DIR, "models")  # Models directory
TRAFFIC_DATA_CSV = os.path.join(PROJECT_DIR, "traffic_data.csv")  # Traffic data CSV
SCALER_FILE = os.path.join(PROJECT_DIR, "scaler.joblib")  # Scaler file
IDS_LOG = os.path.join(PROJECT_DIR, "ids_log.txt")  # Log file

class IntrusionDetectionSystem:
    def __init__(self, model_path, feature_names_path, interface=None, log_file=IDS_LOG, buffer_size=1000, csv_output=TRAFFIC_DATA_CSV, detect_internal=False):
        self.model = joblib.load(model_path)
        self.feature_names = joblib.load(feature_names_path)
        self.setup_logging(log_file)
        self.scaler = StandardScaler()
        self.load_scaler()
        self.buffer = deque(maxlen=buffer_size)
        self.csv_output = csv_output
        self.interface = interface
        self.feature_extractor = NetworkFeatureExtractor(self.interface, detect_internal=detect_internal)
        self.feature_set = set(self.feature_names)
        self.packet_count = 0
        self.start_time = time.time()
        self.buffer_lock = threading.Lock()
        self.processing_thread = None
        self.stop_flag = threading.Event()
        self.anomaly_count = 0
        self.normal_count = 0
        self.last_summary_time = time.time()
        self.anomaly_sources = Counter()
        self.normal_index = np.where(self.model.classes_ == "normal")[0][0]
        self.anomaly_index = np.where(self.model.classes_ == "anomaly")[0][0]
        self.initialize_csv()
        self.smtp_port = 587
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.is_active = False
        self.packet_count_peroid = 0
        self.normal_count_period = 0
        self.anomaly_count_period = 0
        
        try:
            self.email_settings = EmailSettings.objects.get(pk=1)
        except ObjectDoesNotExist:
            self.email_settings = None

    def setup_logging(self, log_file):
        logging.basicConfig(filename=log_file, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        self.logger = logging.getLogger()

    @staticmethod
    def get_available_interfaces():
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)

    def set_interface(self, interface):
        self.interface = interface
        self.feature_extractor = NetworkFeatureExtractor(self.interface)
    
    def load_scaler(self, path=SCALER_FILE):
        try:
            self.scaler = joblib.load(path)
            self.scaler_fitted = True
            self.logger.info(f"Scaler loaded from {path}")
        except FileNotFoundError:
            self.logger.warning(
                f"Scaler file not found at {path}, will fit scaler during runtime")
            self.scaler_fitted = False
        except Exception as e:
            self.logger.error(f"Error loading scaler: {str(e)}")
            self.scaler_fitted = False

    def save_scaler(self, path=SCALER_FILE):
        if self.scaler_fitted:
            joblib.dump(self.scaler, path)
            self.logger.info(f"Scaler saved to {path}")
        else:
            self.logger.warning("Scaler not fitted, cannot save")

    def start_detection(self, duration=None):
        self.logger.info(f"Starting Intrusion Detection System on interface: {self.interface}")
        self.is_active = True
        self.start_time = time.time()
        self.stop_flag.clear()
        self.processing_thread = threading.Thread(target=self.process_buffer)
        self.processing_thread.start()

        try:
            scapy.sniff(iface=self.interface,
                        prn=self.capture_packet, store=0, timeout=duration)
        except KeyboardInterrupt:
            self.logger.info(
                "Stopping packet capture due to KeyboardInterrupt")
        except Exception as e:
            self.logger.error(f"Unexpected error in packet capture: {str(e)}")
            self.logger.error(traceback.format_exc())
        finally:
            self.stop_detection()

    def stop_detection(self):
        self.logger.info("Stopping Intrusion Detection System")
        self.is_active = False
        self.stop_flag.set()
        if self.processing_thread:
            self.processing_thread.join()
        self.logger.info("Intrusion Detection System stopped")
        self.log_performance_metrics()
        self.save_scaler()

    def is_running(self):
        return self.is_active

    def capture_packet(self, packet):
        try:
            with self.buffer_lock:
                self.buffer.append(packet)
        except Exception as e:
            self.logger.error(f"Error capturing packet: {str(e)}")

    def detect_network_interface(self):
        active_interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2:  # IPv4
                    active_interfaces.append(interface)
                    break

        if not active_interfaces:
            raise ValueError("No active network interfaces found.")

        if len(active_interfaces) == 1:
            self.logger.info(
                f"Automatically selected network interface: {active_interfaces[0]}")
            return active_interfaces[0]
        else:
            print("Multiple active network interfaces found. Please choose one:")
            for i, interface in enumerate(active_interfaces):
                print(f"{i + 1}. {interface}")

            while True:
                try:
                    choice = int(
                        input("Enter the number of your choice: ")) - 1
                    if 0 <= choice < len(active_interfaces):
                        self.logger.info(
                            f"Selected network interface: {active_interfaces[choice]}")
                        return active_interfaces[choice]
                    else:
                        print("Invalid choice. Please try again.")
                except ValueError:
                    print("Invalid input. Please enter a number.")

    def process_buffer(self):
        while not self.stop_flag.is_set() or self.buffer:
            packets_to_process = []
            with self.buffer_lock:
                while self.buffer and len(packets_to_process) < 100:
                    packets_to_process.append(self.buffer.popleft())

            for packet in packets_to_process:
                self.process_packet(packet)

            self.print_periodic_summary()

            if not packets_to_process:
                time.sleep(0.1)  # Avoid busy-waiting

    def process_packet(self, packet):
        try:
            features = self.feature_extractor.extract_features(packet)

            if features:
                # The internal traffic check is now handled in NetworkFeatureExtractor
                df = pd.DataFrame([features])
                df_aligned = self.align_features(df, self.feature_names)
                df_scaled = pd.DataFrame(self.scaler.transform(
                    df_aligned), columns=self.feature_names)

                prediction = self.model.predict(df_scaled)[0]
                probabilities = self.model.predict_proba(df_scaled)[0]

                self.save_to_csv(features, prediction)

                with self.buffer_lock:  # Use a lock to ensure atomic updates
                    self.packet_count += 1
                    if prediction == "anomaly":
                        self.anomaly_count_period += 1
                        self.anomaly_count += 1
                        self.log_intrusion(
                            packet, features, probabilities[self.anomaly_index])
                    elif prediction == "normal":
                        self.normal_count_period += 1
                        self.normal_count += 1
                        self.log_normal(packet, features,
                                        probabilities[self.normal_index])

        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            self.logger.error(f"Packet causing error: {packet.summary()}")
            self.logger.error(traceback.format_exc())

    @staticmethod
    def align_features(sample_data, feature_names):
        # Create a DataFrame with all expected features, filled with zeros
        aligned_data = pd.DataFrame(
            0, index=sample_data.index, columns=feature_names)

        # Update the aligned_data with the values from sample_data where they exist
        for col in sample_data.columns:
            if col in feature_names:
                aligned_data[col] = sample_data[col]

        return aligned_data
    

    def log_intrusion(self, packet, features, probability):
        src_ip = packet[IP].src if IP in packet else "Unknown"
        dst_ip = packet[IP].dst if IP in packet else "Unknown"
        protocol = features['protocol_type']
        service = features['service']

        severity = "HIGH" if probability > 0.8 else "MEDIUM" if probability > 0.6 else "LOW"

        log_message = (f"ALERT: Potential intrusion detected! - {severity}\n"
                       f"Source IP: {src_ip}, Destination IP: {dst_ip}\n"
                       f"Protocol: {protocol}, Service: {service}\n"
                       f"Confidence: {probability:.2f}\n"
                       f"Features: {features}")

        # if severity in ["HIGH", "MEDIUM"]:
        #    print(log_message)

        self.logger.warning(log_message)
        self.anomaly_sources[src_ip] += 1

    def log_normal(self, packet, features, probability):
        src_ip = packet[IP].src if IP in packet else "Unknown"
        dst_ip = packet[IP].dst if IP in packet else "Unknown"
        protocol = features['protocol_type']
        service = features['service']

        log_message = (f"Normal traffic detected\n"
                       f"Source IP: {src_ip}, Destination IP: {dst_ip}\n"
                       f"Protocol: {protocol}, Service: {service}\n"
                       f"Confidence: {probability:.2f}")

        self.logger.info(log_message)

    def print_periodic_summary(self):
        current_time = time.time()
        if current_time - self.last_summary_time >= 180:  # 3 minutes
            total_packets = self.normal_count_period + self.anomaly_count_period
            summary = (f"\n--- Last 3 minutes summary ---\n"
                       f"Total packets: {total_packets}\n"
                       f"Normal: {self.normal_count_period}\n"
                       f"Anomalies: {self.anomaly_count_period}\n"
                       f"Top source of anomalies: {self.anomaly_sources.most_common(1)[0] if self.anomaly_sources else 'None'}\n")
            print(summary)
            self.logger.info(summary)
            self.last_summary_time = current_time
            self.normal_count_period = 0
            self.anomaly_count_period = 0
            self.anomaly_sources.clear()

    def log_performance_metrics(self):
        elapsed_time = time.time() - self.start_time
        packets_per_second = self.packet_count / elapsed_time
        self.logger.info(
            f"Performance: {packets_per_second:.2f} packets/second")
        self.logger.info(f"Total packets: {self.packet_count}")
        self.logger.info(f"Normal packets: {self.normal_count}")
        self.logger.info(f"Anomaly packets: {self.anomaly_count}")

    def send_alert(self, message):
        if not self.email_settings:
            self.logger.warning("Email settings not configured. Alert not sent.")
            return
        
        msg = MIMEMultipart()
        msg['From'] = self.email_settings.email_sender
        msg['To'] = self.email_settings.email_recipient
        msg['Subject'] = 'IDS Alert'

        html_content = """
        <html>
        <head></head>
        <body>
            <p>{}</p>
        </body>
        </html>
        """.format(message.replace('\n', '<br>'))

        msg.attach(MIMEText(html_content, 'html'))

        try:
            with smtplib.SMTP(self.email_settings.smtp_server, self.email_settings.smtp_port) as server:
                server.starttls()
                server.login(self.email_settings.email_sender, self.email_settings.email_password)
                server.send_message(msg)
                self.logger.info("Alert email sent successfully")
        except Exception as e:
            self.logger.error(f"Failed to send alert email: {str(e)}")
            self.logger.error(traceback.format_exc())

    def initialize_csv(self):
        header = [
            "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
            "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
            "num_compromised", "root_shell", "su_attempted", "num_root",
            "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
            "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
            "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
            "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
            "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "class"
        ]
        with open(self.csv_output, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header)

    def save_to_csv(self, features, prediction):
        row = [
            features.get('duration', 0),
            features.get('protocol_type', ''),
            features.get('service', ''),
            features.get('flag', ''),
            features.get('src_bytes', 0),
            features.get('dst_bytes', 0),
            features.get('land', 0),
            features.get('wrong_fragment', 0),
            features.get('urgent', 0),
            features.get('hot', 0),
            features.get('num_failed_logins', 0),
            features.get('logged_in', 0),
            features.get('num_compromised', 0),
            features.get('root_shell', 0),
            features.get('su_attempted', 0),
            features.get('num_root', 0),
            features.get('num_file_creations', 0),
            features.get('num_shells', 0),
            features.get('num_access_files', 0),
            features.get('num_outbound_cmds', 0),
            features.get('is_host_login', 0),
            features.get('is_guest_login', 0),
            features.get('count', 0),
            features.get('srv_count', 0),
            features.get('serror_rate', 0),
            features.get('srv_serror_rate', 0),
            features.get('rerror_rate', 0),
            features.get('srv_rerror_rate', 0),
            features.get('same_srv_rate', 0),
            features.get('diff_srv_rate', 0),
            features.get('srv_diff_host_rate', 0),
            features.get('dst_host_count', 0),
            features.get('dst_host_srv_count', 0),
            features.get('dst_host_same_srv_rate', 0),
            features.get('dst_host_diff_srv_rate', 0),
            features.get('dst_host_same_src_port_rate', 0),
            features.get('dst_host_srv_diff_host_rate', 0),
            features.get('dst_host_serror_rate', 0),
            features.get('dst_host_srv_serror_rate', 0),
            features.get('dst_host_rerror_rate', 0),
            features.get('dst_host_srv_rerror_rate', 0),
            prediction
        ]
        with open(self.csv_output, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(row)


if __name__ == "__main__":
    model_path = "models/NSL-KDD-RF-model.joblib"
    feature_names_path = "models/feature_names.pkl"
    ids = IntrusionDetectionSystem(model_path, feature_names_path)
    ids.start_detection(duration=None)
