#!/usr/bin/env python3
"""
WiFi Packet Sniffer - Serial Data Collector
Reads feature data from ESP32 serial port and writes to CSV file
"""

import serial
import csv
import time
import sys
from datetime import datetime
from pathlib import Path

class SerialDataCollector:
    """Collects WiFi flow data from ESP32 serial port and writes to CSV"""
    
    # CSV Headers (matching paper's features - TABLE I)
    HEADERS = [
        'flow_id',
        'flow_ip_src',
        'flow_ip_dst',
        'flow_srcport',
        'flow_dstport',
        'flow_proto',
        'num_packets',
        'total_length',
        'avg_packet_size',
        'min_time',
        'max_time',
        'tcp_window_size_avg',
        'total_payload',
        'forward_packets',
        'receiving_packets',
        'fragments',
        'flow_duration',
        'target'
    ]
    
    def __init__(self, port='/dev/ttyUSB0', baudrate=115200, output_file='wifi_dataset.csv'):
        """
        Initialize the data collector
        
        Args:
            port: Serial port (e.g., '/dev/ttyUSB0')
            baudrate: Serial baud rate
            output_file: Output CSV file path
        """
        self.port = port
        self.baudrate = baudrate
        self.output_file = output_file
        self.serial_conn = None
        self.csv_file = None
        self.csv_writer = None
        self.flow_count = 0
        self.start_time = None
        self.last_status = 0
        
    def connect(self) -> bool:
        """Establish serial connection"""
        try:
            print(f"[*] Connecting to {self.port} at {self.baudrate} baud...")
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=1
            )
            time.sleep(2)  # Wait for ESP32 to initialize
            print(f"[+] Connected successfully\n")
            return True
        except Exception as e:
            print(f"[-] Failed to connect: {e}")
            return False
    
    def initialize_csv(self) -> bool:
        """Initialize CSV file with headers"""
        try:
            print(f"[*] Creating CSV file: {self.output_file}")
            self.csv_file = open(self.output_file, 'w', newline='')
            self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=self.HEADERS)
            self.csv_writer.writeheader()
            self.csv_file.flush()
            print(f"[+] CSV headers written\n")
            return True
        except Exception as e:
            print(f"[-] Failed to initialize CSV: {e}")
            return False
    
    def parse_data_line(self, line: str) -> dict or None:
        """
        Parse a DATA line from ESP32
        
        Format: DATA|field1|field2|...|field18
        
        Args:
            line: Raw serial line
            
        Returns:
            Dictionary with parsed data or None if invalid
        """
        try:
            if not line.startswith('DATA|'):
                return None
            
            parts = line.split('|')
            if len(parts) != 19:  # DATA + 18 fields
                return None
            
            # Create dictionary with values
            flow_data = {}
            for i, header in enumerate(self.HEADERS):
                flow_data[header] = parts[i + 1]  # Skip 'DATA' at index 0
            
            return flow_data
        except Exception as e:
            print(f"[!] Parse error: {e}")
            return None
    
    def write_flow(self, flow_data: dict) -> bool:
        """Write a flow to CSV file"""
        try:
            self.csv_writer.writerow(flow_data)
            self.csv_file.flush()
            self.flow_count += 1
            return True
        except Exception as e:
            print(f"[!] Write error: {e}")
            return False
    
    def print_status(self, force=False):
        """Print collection status"""
        current_time = time.time()
        
        # Print every 30 seconds or forced
        if force or (current_time - self.last_status) > 30:
            self.last_status = current_time
            elapsed = current_time - self.start_time
            flow_rate = self.flow_count / elapsed if elapsed > 0 else 0
            
            print(f"[STATUS] Elapsed: {int(elapsed)}s | Flows: {self.flow_count} | Rate: {flow_rate:.1f} flows/sec")
    
    def start_collection(self, duration: int = None):
        """
        Start collecting data
        
        Args:
            duration: Collection duration in seconds (None = indefinite)
        """
        if not self.connect():
            return
        
        if not self.initialize_csv():
            self.disconnect()
            return
        
        self.start_time = time.time()
        print(f"[*] Starting data collection...")
        print(f"[*] Output file: {self.output_file}")
        if duration:
            print(f"[*] Duration: {duration} seconds")
        print(f"[*] Press Ctrl+C to stop\n")
        print("-" * 60)
        
        try:
            while True:
                # Check duration limit
                if duration:
                    elapsed = time.time() - self.start_time
                    if elapsed > duration:
                        print(f"\n[*] Reached target duration ({duration}s)")
                        break
                
                # Read from serial
                try:
                    if self.serial_conn.in_waiting:
                        line = self.serial_conn.readline().decode('utf-8').strip()
                        
                        if line:
                            # Check for status messages
                            if line.startswith('[STATUS]'):
                                print(f"[ESP32] {line}")
                            elif line.startswith('[START_DATA_COLLECTION]'):
                                print(f"[+] ESP32 data collection started\n")
                            elif line.startswith('[OK]') or line.startswith('Initializing') or line.startswith('Outputting'):
                                # Skip setup messages
                                pass
                            elif line.startswith('DATA|'):
                                # Parse and write flow data
                                flow_data = self.parse_data_line(line)
                                if flow_data:
                                    self.write_flow(flow_data)
                                    self.print_status()
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"[!] Serial read error: {e}")
                    continue
        
        except KeyboardInterrupt:
            print(f"\n[*] Collection interrupted by user")
        
        finally:
            self.finalize()
    
    def disconnect(self):
        """Close serial connection"""
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
            print(f"[+] Serial connection closed")
    
    def finalize(self):
        """Close files and display final statistics"""
        if self.csv_file:
            self.csv_file.close()
            print(f"[+] CSV file closed")
        
        self.disconnect()
        
        elapsed = time.time() - self.start_time
        flow_rate = self.flow_count / elapsed if elapsed > 0 else 0
        
        print(f"\n" + "=" * 60)
        print(f"COLLECTION COMPLETE")
        print(f"=" * 60)
        print(f"Output file: {self.output_file}")
        print(f"Total flows: {self.flow_count}")
        print(f"Duration: {int(elapsed)}s ({elapsed/60:.1f} minutes)")
        print(f"Flow rate: {flow_rate:.2f} flows/sec")
        print(f"=" * 60)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Collect WiFi flow data from ESP32 and save to CSV'
    )
    parser.add_argument('--port', default='/dev/ttyUSB0', help='Serial port')
    parser.add_argument('--baudrate', type=int, default=115200, help='Baud rate')
    parser.add_argument('--output', default='wifi_dataset.csv', help='Output CSV file')
    parser.add_argument('--duration', type=int, default=None, help='Collection duration in seconds')
    
    args = parser.parse_args()
    
    # Create collector and start
    collector = SerialDataCollector(
        port=args.port,
        baudrate=args.baudrate,
        output_file=args.output
    )
    
    collector.start_collection(duration=args.duration)


if __name__ == '__main__':
    main()
