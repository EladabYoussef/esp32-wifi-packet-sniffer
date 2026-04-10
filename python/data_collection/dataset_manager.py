#!/usr/bin/env python3
"""
Dataset Utility Script
Combines normal and attack traffic datasets, performs basic analysis
"""

import pandas as pd
import os
from pathlib import Path
from typing import Tuple

class DatasetManager:
    """Manages WiFi traffic datasets"""
    
    def __init__(self, output_dir='./'):
        """Initialize dataset manager"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def combine_datasets(self, normal_file: str, attack_file: str, 
                        output_file: str = 'combined_dataset.csv') -> pd.DataFrame:
        """
        Combine normal and attack traffic datasets
        
        Args:
            normal_file: Path to normal traffic CSV
            attack_file: Path to attack traffic CSV
            output_file: Output combined CSV filename
            
        Returns:
            Combined DataFrame
        """
        print(f"[*] Loading normal traffic data from: {normal_file}")
        try:
            normal_df = pd.read_csv(normal_file)
            print(f"[+] Loaded {len(normal_df)} normal flows")
        except FileNotFoundError:
            print(f"[-] Normal traffic file not found: {normal_file}")
            return None
        
        print(f"[*] Loading attack traffic data from: {attack_file}")
        try:
            attack_df = pd.read_csv(attack_file)
            print(f"[+] Loaded {len(attack_df)} attack flows")
        except FileNotFoundError:
            print(f"[-] Attack traffic file not found: {attack_file}")
            return None
        
        print(f"\n[*] Combining datasets...")
        combined_df = pd.concat([normal_df, attack_df], ignore_index=True)
        
        # Verify labels
        normal_count = len(combined_df[combined_df['target'] == 0])
        attack_count = len(combined_df[combined_df['target'] == 1])
        
        print(f"[+] Combined dataset created:")
        print(f"    Total flows: {len(combined_df)}")
        print(f"    Normal flows (0): {normal_count} ({100*normal_count/len(combined_df):.1f}%)")
        print(f"    Attack flows (1): {attack_count} ({100*attack_count/len(combined_df):.1f}%)")
        
        # Save combined dataset
        output_path = self.output_dir / output_file
        print(f"\n[*] Saving combined dataset to: {output_path}")
        combined_df.to_csv(output_path, index=False)
        print(f"[+] Combined dataset saved successfully")
        
        return combined_df
    
    def analyze_dataset(self, csv_file: str) -> dict:
        """
        Analyze dataset statistics
        
        Args:
            csv_file: Path to CSV file
            
        Returns:
            Dictionary with analysis results
        """
        print(f"\n[*] Analyzing dataset: {csv_file}")
        
        try:
            df = pd.read_csv(csv_file)
        except FileNotFoundError:
            print(f"[-] File not found: {csv_file}")
            return None
        
        print(f"\n{'='*60}")
        print(f"DATASET ANALYSIS")
        print(f"{'='*60}")
        
        print(f"\n1. OVERALL STATISTICS")
        print(f"   Total flows: {len(df)}")
        print(f"   Columns: {len(df.columns)}")
        print(f"   Features: {list(df.columns)}")
        
        if 'target' in df.columns:
            print(f"\n2. CLASS DISTRIBUTION")
            class_dist = df['target'].value_counts()
            for label, count in class_dist.items():
                label_name = "Attack" if label == 1 else "Normal"
                percentage = 100 * count / len(df)
                print(f"   {label_name} ({label}): {count} flows ({percentage:.1f}%)")
        
        print(f"\n3. NUMERIC FEATURE STATISTICS")
        numeric_df = df.select_dtypes(include=['int64', 'float64'])
        print(f"   {numeric_df.describe().to_string()}")
        
        print(f"\n4. PROTOCOL DISTRIBUTION")
        if 'flow_proto' in df.columns:
            proto_dist = df['flow_proto'].value_counts()
            protocol_names = {
                6: 'TCP',
                17: 'UDP',
                1: 'ICMP',
                0: 'IP'
            }
            for proto, count in proto_dist.items():
                proto_name = protocol_names.get(int(proto), f"Unknown({proto})")
                percentage = 100 * count / len(df)
                print(f"   {proto_name}: {count} flows ({percentage:.1f}%)")
        
        print(f"\n5. FLOW DURATION STATISTICS")
        if 'flow_duration' in df.columns:
            print(f"   Min: {df['flow_duration'].min()} ms")
            print(f"   Max: {df['flow_duration'].max()} ms")
            print(f"   Mean: {df['flow_duration'].mean():.1f} ms")
            print(f"   Median: {df['flow_duration'].median():.1f} ms")
        
        print(f"\n6. PACKET COUNT STATISTICS")
        if 'num_packets' in df.columns:
            print(f"   Min: {df['num_packets'].min()} packets")
            print(f"   Max: {df['num_packets'].max()} packets")
            print(f"   Mean: {df['num_packets'].mean():.1f} packets")
            print(f"   Median: {df['num_packets'].median():.1f} packets")
        
        print(f"\n{'='*60}\n")
        
        return {
            'total_flows': len(df),
            'num_features': len(df.columns),
            'columns': list(df.columns)
        }
    
    def split_train_test(self, csv_file: str, train_ratio: float = 0.8,
                        output_prefix: str = 'dataset') -> Tuple[str, str]:
        """
        Split dataset into train/test sets
        
        Args:
            csv_file: Path to combined CSV
            train_ratio: Ratio for training set (0.0-1.0)
            output_prefix: Prefix for output filenames
            
        Returns:
            Tuple of (train_file, test_file) paths
        """
        print(f"\n[*] Loading dataset: {csv_file}")
        
        try:
            df = pd.read_csv(csv_file)
        except FileNotFoundError:
            print(f"[-] File not found: {csv_file}")
            return None, None
        
        # Stratified split by label to maintain class distribution
        train_df = df.sample(frac=train_ratio, random_state=42)
        test_df = df.drop(train_df.index)
        
        train_file = self.output_dir / f"{output_prefix}_train.csv"
        test_file = self.output_dir / f"{output_prefix}_test.csv"
        
        print(f"\n[*] Splitting dataset (train: {train_ratio*100:.0f}%, test: {(1-train_ratio)*100:.0f}%)")
        print(f"   Train: {len(train_df)} flows")
        print(f"   Test: {len(test_df)} flows")
        
        # Verify class distribution maintained
        if 'target' in df.columns:
            print(f"\n[*] Verifying class distribution...")
            for dataset_name, dataset in [("Train", train_df), ("Test", test_df)]:
                dist = dataset['target'].value_counts()
                print(f"   {dataset_name}:")
                for label, count in dist.items():
                    label_name = "Attack" if label == 1 else "Normal"
                    pct = 100 * count / len(dataset)
                    print(f"      {label_name}: {count} ({pct:.1f}%)")
        
        print(f"\n[*] Saving splits...")
        train_df.to_csv(train_file, index=False)
        test_df.to_csv(test_file, index=False)
        print(f"[+] Train set: {train_file}")
        print(f"[+] Test set: {test_file}")
        
        return str(train_file), str(test_file)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='WiFi Dataset Manager')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Combine command
    combine_parser = subparsers.add_parser('combine', help='Combine normal and attack datasets')
    combine_parser.add_argument('normal', help='Normal traffic CSV file')
    combine_parser.add_argument('attack', help='Attack traffic CSV file')
    combine_parser.add_argument('--output', default='combined_dataset.csv', 
                               help='Output CSV filename')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze dataset')
    analyze_parser.add_argument('dataset', help='Dataset CSV file')
    
    # Split command
    split_parser = subparsers.add_parser('split', help='Split dataset into train/test')
    split_parser.add_argument('dataset', help='Combined dataset CSV file')
    split_parser.add_argument('--train-ratio', type=float, default=0.8,
                             help='Training set ratio (0.0-1.0, default: 0.8)')
    split_parser.add_argument('--prefix', default='dataset',
                             help='Output filename prefix')
    
    args = parser.parse_args()
    
    manager = DatasetManager()
    
    if args.command == 'combine':
        manager.combine_datasets(args.normal, args.attack, args.output)
    
    elif args.command == 'analyze':
        manager.analyze_dataset(args.dataset)
    
    elif args.command == 'split':
        manager.split_train_test(args.dataset, args.train_ratio, args.prefix)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
