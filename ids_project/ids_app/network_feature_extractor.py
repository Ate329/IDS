import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from collections import defaultdict, deque
import time
import re
from typing import Dict, Tuple, Set, List, Optional
from dataclasses import dataclass, field


@dataclass
class Connection:
    start_time: float = 0
    last_time: float = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    count: int = 0
    srv_count: int = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    urgent: int = 0
    hot: int = 0
    num_failed_logins: int = 0
    logged_in: int = 0
    num_compromised: int = 0
    root_shell: int = 0
    su_attempted: int = 0
    num_root: int = 0
    num_file_creations: int = 0
    num_shells: int = 0
    num_access_files: int = 0
    num_outbound_cmds: int = 0
    is_host_login: int = 0
    is_guest_login: int = 0
    land: int = 0
    wrong_fragment: int = 0
    same_srv_connections: List[Tuple] = field(default_factory=list)
    diff_host_services: Set[int] = field(default_factory=set)
    flags: List[str] = field(default_factory=list)


@dataclass
class HostStats:
    count: int = 0
    srv_count: int = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    same_src_port_rate: float = 0
    srv_diff_host_rate: float = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    last_port: int = 0
    connections: deque = field(default_factory=lambda: deque(maxlen=100))


class NetworkFeatureExtractor:
    __slots__ = ('interface', 'timeout', 'connections', 'host_stats',
                 'recent_connections', 'two_second_connections', 'detect_internal')

    COMMON_PORTS = {
        80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 20: 'ftp_data',
        23: 'telnet', 25: 'smtp', 53: 'domain', 110: 'pop3', 143: 'imap',
        512: 'exec', 513: 'login', 514: 'shell', 520: 'efs'
    }

    PROTOCOL_TYPES = {6: 'tcp', 17: 'udp', 1: 'icmp'}

    def __init__(self, interface: str = "wlp1s0", timeout: int = 60, detect_internal: bool = False):
        self.interface = interface
        self.timeout = timeout
        self.connections: Dict[Tuple, Connection] = defaultdict(Connection)
        self.host_stats: Dict[str, HostStats] = defaultdict(HostStats)
        self.recent_connections: deque = deque(maxlen=100)
        self.two_second_connections: List[Tuple[Connection, float]] = []
        self.detect_internal = detect_internal
    
    def _is_internal_traffic(self, packet: scapy.Packet) -> bool:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            return self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip)
        return False

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        return ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', 
                            '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', 
                            '172.28.', '172.29.', '172.30.', '172.31.', '192.168.'))
        
    def extract_features(self, packet: scapy.Packet) -> Optional[Dict]:
        if ARP in packet:
            # Handle ARP packets
            return self._extract_arp_features(packet)
        elif IP in packet:
            if not self.detect_internal and self._is_internal_traffic(packet):
                return None
            
            if TCP in packet or UDP in packet or ICMP in packet:
                return self._extract_ip_features(packet)
        
        # If it's not an ARP or IP packet, return None
        return None

    def _extract_arp_features(self, packet: scapy.Packet) -> Dict:
        return {
            'protocol_type': 'arp',
            'src_ip': packet[ARP].psrc,
            'dst_ip': packet[ARP].pdst,
            'operation': 'request' if packet[ARP].op == 1 else 'reply'
        }

    def _extract_ip_features(self, packet: scapy.Packet) -> Dict:
        ip = packet[IP]
        transport = packet.getlayer(TCP) or packet.getlayer(
            UDP) or packet.getlayer(ICMP)

        conn_key = self._get_connection_key(ip, transport)
        conn = self.connections[conn_key]

        current_time = time.time()

        self._update_connection(conn, packet, current_time)
        self._update_host_stats(ip.src, ip.dst, getattr(
            transport, 'sport', 0), getattr(transport, 'dport', 0), ip.proto)

        return self._extract_features_dict(ip, transport, conn, conn_key)

    def _get_connection_key(self, ip: IP, transport) -> Tuple:
        return (ip.src, ip.dst, getattr(transport, 'sport', 0), getattr(transport, 'dport', 0), ip.proto)

    def _update_connection(self, conn: Connection, packet: scapy.Packet, current_time: float) -> None:
        if conn.start_time == 0:
            conn.start_time = current_time

        conn.last_time = current_time
        conn.src_bytes += len(packet)
        conn.dst_bytes += len(packet.payload)

        self._update_two_second_stats(conn)
        self._update_connection_services(conn, packet)
        self._update_urgent_and_hot(conn, packet)
        self._update_additional_features(conn, packet)
        self._update_flags(conn, packet)

    def _update_two_second_stats(self, conn: Connection) -> None:
        current_time = time.time()

        self.two_second_connections = [
            (c, t) for c, t in self.two_second_connections if current_time - t <= 2]
        self.two_second_connections.append((conn, current_time))

        conn.count = sum(
            1 for c, _ in self.two_second_connections if c == conn)
        conn.srv_count = sum(
            1 for c, _ in self.two_second_connections if c.same_srv_connections == conn.same_srv_connections)

    def _update_connection_services(self, conn: Connection, packet: scapy.Packet) -> None:
        if TCP in packet or UDP in packet:
            transport = packet[TCP] if TCP in packet else packet[UDP]
            if transport.dport == transport.sport:
                conn.same_srv_connections.append(
                    (packet[IP].src, packet[IP].dst, transport.sport, transport.dport))
            else:
                conn.diff_host_services.add(transport.dport)

    def _update_urgent_and_hot(self, conn: Connection, packet: scapy.Packet) -> None:
        conn.urgent += self._get_urgent(packet)
        conn.hot += self._get_hot(packet, conn)

    def _detect_outbound_cmds(self, packet: scapy.Packet) -> int:
        if TCP in packet and packet[TCP].dport == 80:  # HTTP traffic
            payload = str(packet[TCP].payload)

            # Check for HTTP layer
            if HTTP in packet:
                http_method = packet[HTTP].Method.decode() if hasattr(
                    packet[HTTP], 'Method') else ""
                http_path = packet[HTTP].Path.decode() if hasattr(
                    packet[HTTP], 'Path') else ""

                # Look for common HTTP-based command patterns
                if http_method in ["GET", "POST"] and any(cmd in http_path.lower() for cmd in ["cmd", "exec", "command", "run"]):
                    return 1

            # Check for common command patterns in the payload
            command_patterns = [
                r"\bexec\b",
                r"\beval\b",
                r"\bsystem\b",
                r"\bshell_exec\b",
                r"\bpassthru\b",
                r"\bcmd\.exe\b",
                r"\bbash\b",
                r"\bsh\b",
                r"/bin/",
                r"\bcurl\b",
                r"\bwget\b"
            ]

            if any(re.search(pattern, payload, re.IGNORECASE) for pattern in command_patterns):
                return 1

        elif DNS in packet:  # DNS traffic
            if packet[DNS].qr == 0:  # DNS query
                query = packet[DNS].qd.qname.decode()
                # Look for potential command and control domain patterns
                if any(pattern in query for pattern in [".dyndns.", ".no-ip.", ".serveo.net"]):
                    return 1

        return 0

    def _update_additional_features(self, conn: Connection, packet: scapy.Packet) -> None:
        payload = str(packet.payload)

        if 'create' in payload or 'touch' in payload or 'mkdir' in payload or 'mkfile' in payload:
            conn.num_file_creations += 1

        if 'rlogin' in payload or 'rsh' in payload or 'telnet' in payload:
            conn.is_host_login = 1

        if 'guest' in payload or 'anonymous' in payload:
            conn.is_guest_login = 1

        if any(word in payload for word in ['rootkit', 'exploit', 'vulnerab', 'backdoor']):
            conn.num_compromised += 1

        if 'root' in payload or 'sudo' in payload or 'su' in payload:
            conn.num_root += 1

        if 'login successful' in payload or 'authenticated' in payload:
            conn.logged_in = 1

        if any(word in payload for word in ['chmod', 'chown', 'ls -l', 'ls -la']):
            conn.num_access_files += 1

        # Update num_outbound_cmds
        conn.num_outbound_cmds += self._detect_outbound_cmds(packet)

    def _update_flags(self, conn: Connection, packet: scapy.Packet) -> None:
        if TCP in packet:
            flag = self._get_flag(packet[TCP])
            conn.flags.append(flag)

    def _update_host_stats(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> None:
        host_stats = self.host_stats[dst_ip]
        host_stats.count += 1
        host_stats.srv_count += 1 if host_stats.last_port == dst_port else 0
        host_stats.last_port = dst_port

        recent_connections = list(self.recent_connections)
        recent_connections.append(
            (src_ip, dst_ip, src_port, dst_port, proto, time.time()))

        host_stats.same_srv_rate = sum(
            1 for conn in recent_connections if conn[3] == dst_port) / len(recent_connections)
        host_stats.diff_srv_rate = sum(
            1 for conn in recent_connections if conn[3] != dst_port) / len(recent_connections)
        host_stats.same_src_port_rate = sum(
            1 for conn in recent_connections if conn[2] == src_port) / len(recent_connections)
        host_stats.srv_diff_host_rate = sum(
            1 for conn in recent_connections if conn[1] != dst_ip) / len(recent_connections)
        host_stats.serror_rate = sum(1 for conn in recent_connections if self._is_serror(
            self.connections[(conn[0], conn[1], conn[2], conn[3], conn[4])])) / len(recent_connections)
        host_stats.srv_serror_rate = sum(1 for conn in recent_connections if self._is_serror(
            self.connections[(conn[0], conn[1], conn[2], conn[3], conn[4])])) / len(recent_connections)
        host_stats.rerror_rate = sum(1 for conn in recent_connections if self._is_rerror(
            self.connections[(conn[0], conn[1], conn[2], conn[3], conn[4])])) / len(recent_connections)
        host_stats.srv_rerror_rate = sum(1 for conn in recent_connections if self._is_rerror(
            self.connections[(conn[0], conn[1], conn[2], conn[3], conn[4])])) / len(recent_connections)

        self.recent_connections = deque(recent_connections, maxlen=100)

    def _extract_features_dict(self, ip: IP, transport, conn: Connection, conn_key: Tuple) -> Dict:
        return {
            'duration': conn.last_time - conn.start_time,
            'protocol_type': self._get_protocol_type(ip.proto),
            'service': self._get_service(transport.dport),
            'flag': self._get_flag(transport),
            'src_bytes': conn.src_bytes,
            'dst_bytes': conn.dst_bytes,
            'land': int(ip.src == ip.dst and getattr(transport, 'sport', 0) == getattr(transport, 'dport', 0)),
            'wrong_fragment': self._get_wrong_fragment(ip),
            'urgent': conn.urgent,
            'hot': conn.hot,
            'num_failed_logins': conn.num_failed_logins,
            'logged_in': conn.logged_in,
            'num_compromised': conn.num_compromised,
            'root_shell': conn.root_shell,
            'su_attempted': conn.su_attempted,
            'num_root': conn.num_root,
            'num_file_creations': conn.num_file_creations,
            'num_shells': conn.num_shells,
            'num_access_files': conn.num_access_files,
            'num_outbound_cmds': conn.num_outbound_cmds,
            'is_host_login': conn.is_host_login,
            'is_guest_login': conn.is_guest_login,
            'count': conn.count,
            'srv_count': conn.srv_count,
            'serror_rate': self._calculate_rate(conn, self._is_serror),
            'srv_serror_rate': self._calculate_srv_rate(conn, self._is_serror),
            'rerror_rate': self._calculate_rate(conn, self._is_rerror),
            'srv_rerror_rate': self._calculate_srv_rate(conn, self._is_rerror),
            'same_srv_rate': self._calculate_rate(conn, self._is_same_srv),
            'diff_srv_rate': self._calculate_rate(conn, self._is_diff_srv),
            'srv_diff_host_rate': self._calculate_srv_rate(conn, self._is_diff_host),
            'dst_host_count': self.host_stats[ip.dst].count,
            'dst_host_srv_count': self.host_stats[ip.dst].srv_count,
            'dst_host_same_srv_rate': self.host_stats[ip.dst].same_srv_rate,
            'dst_host_diff_srv_rate': self.host_stats[ip.dst].diff_srv_rate,
            'dst_host_same_src_port_rate': self.host_stats[ip.dst].same_src_port_rate,
            'dst_host_srv_diff_host_rate': self.host_stats[ip.dst].srv_diff_host_rate,
            'dst_host_serror_rate': self.host_stats[ip.dst].serror_rate,
            'dst_host_srv_serror_rate': self.host_stats[ip.dst].srv_serror_rate,
            'dst_host_rerror_rate': self.host_stats[ip.dst].rerror_rate,
            'dst_host_srv_rerror_rate': self.host_stats[ip.dst].srv_rerror_rate
        }

    def _calculate_rate(self, conn: Connection, condition) -> float:
        if conn.count == 0:
            return 0.0
        return sum(1 for c, _ in self.two_second_connections if condition(c)) / conn.count

    def _calculate_srv_rate(self, conn: Connection, condition) -> float:
        if conn.srv_count == 0:
            return 0.0
        return sum(1 for c, _ in self.two_second_connections if condition(c)) / conn.srv_count

    def _is_serror(self, conn: Connection) -> bool:
        return any('S' in flag and 'F' not in flag and 'A' not in flag for flag in conn.flags)

    def _is_rerror(self, conn: Connection) -> bool:
        return any('R' in flag for flag in conn.flags)

    def _is_same_srv(self, conn: Connection) -> bool:
        return len(set(conn.same_srv_connections)) == 1

    def _is_diff_srv(self, conn: Connection) -> bool:
        return len(set(conn.same_srv_connections)) > 1

    def _is_diff_host(self, conn: Connection) -> bool:
        return len(conn.diff_host_services) > 1

    @staticmethod
    def _get_protocol_type(protocol: int) -> str:
        return NetworkFeatureExtractor.PROTOCOL_TYPES.get(protocol, 'other')

    @staticmethod
    def _get_service(port: int) -> str:
        return NetworkFeatureExtractor.COMMON_PORTS.get(port, 'other')

    @staticmethod
    def _get_flag(transport) -> str:
        if isinstance(transport, ICMP):
            return 'SF'

        if not hasattr(transport, 'flags'):
            return 'OTH'

        flags = ''.join(flag for bit, flag in [
            (0x01, 'F'), (0x02, 'S'), (0x04, 'R'),
            (0x08, 'P'), (0x10, 'A'), (0x20, 'U')
        ] if transport.flags & bit)

        if not flags:
            return 'OTH'
        elif 'S' in flags and 'F' in flags:
            return 'SF'
        elif 'S' in flags:
            return 'S0'
        elif 'F' in flags:
            return 'REJ'
        elif 'R' in flags:
            return 'RSTO'
        elif 'R' in flags and 'A' in flags:
            return 'RSTR'
        else:
            return flags

    @staticmethod
    def _get_wrong_fragment(ip: IP) -> int:
        return int(ip.frag != 0 or ip.flags.MF)

    @staticmethod
    def _get_urgent(packet: scapy.Packet) -> int:
        return int(getattr(packet.getlayer(TCP), 'urgptr', 0) > 0)

    @staticmethod
    def _get_hot(packet: scapy.Packet, conn: Connection) -> int:
        hot = 0
        payload = str(packet.payload)

        sensitive_paths = ['/etc/', '/usr/', '/var/', '/root/']
        sensitive_files = ['/etc/passwd', '/etc/shadow', '.ssh/id_rsa']
        sensitive_commands = ['gcc', 'make', 'sudo', 'su']

        hot += sum(2 for file in sensitive_files if file in payload)
        hot += sum(1 for path in sensitive_paths if path in payload)
        hot += sum(1 for cmd in sensitive_commands if cmd in payload)

        if 'root' in payload and ('shell' in payload or 'bash' in payload):
            hot += 2
            conn.root_shell = 1

        if 'su ' in payload:
            hot += 1
            conn.su_attempted = 1

        if 'login failed' in payload.lower():
            conn.num_failed_logins += 1

        if 'shell' in payload.lower():
            conn.num_shells += 1

        return hot

    def start_capture(self) -> None:
        print(f"Starting packet capture on interface {self.interface}")
        scapy.sniff(iface=self.interface, prn=self.process_packet,
                    store=False, timeout=self.timeout)

    def process_packet(self, packet: scapy.Packet) -> Optional[Dict]:
        features = self.extract_features(packet)
        return features


if __name__ == "__main__":
    extractor = NetworkFeatureExtractor()
    extractor.start_capture()
