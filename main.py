#!/usr/bin/env python3
import argparse
from itertools import product
import re
from urllib.parse import urlparse, urljoin
import os
import requests
import concurrent.futures
from typing import List, Set
import time
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求的警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class BackupScanner:
    def __init__(self, url: str, status_codes: List[int], threads: int = 10, timeout: int = 5):
        self.base_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        self.status_codes = status_codes
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        # 设置请求头
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # 设置会话参数
        self.session.verify = False  # 禁用 SSL 验证
        self.session.headers.update(self.headers)

    def check_backup_file(self, backup_name: str) -> tuple:
        """检查单个备份文件是否存在"""
        url = urljoin(self.base_url, backup_name)
        try:
            resp = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            status_code = resp.status_code
            if status_code in self.status_codes:
                # 如果HEAD请求成功，再试试GET请求
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                status_code = resp.status_code
                if status_code in self.status_codes:
                    return (True, url, status_code, len(resp.content))
            return (False, url, status_code, 0)
        except RequestException:
            return (False, url, 0, 0)

    def scan_backup_files(self, backup_names: Set[str]):
        """并发扫描所有备份文件"""
        print(f"\n开始扫描 {len(backup_names)} 个可能的备份文件...")
        print(f"目标状态码: {self.status_codes}")
        print("=" * 60)

        found_files = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.check_backup_file, name): name 
                           for name in backup_names}
            
            for future in concurrent.futures.as_completed(future_to_url):
                success, url, status_code, size = future.result()
                # 打印每个请求的结果
                status_str = f"{status_code}" if status_code > 0 else "ERR"
                print(f"{url}{'-' * (60 - len(url))}{status_str}")
                
                if success:
                    found_files.append((url, status_code, size))

        print("\n" + "=" * 60)
        if found_files:
            print(f"\n发现 {len(found_files)} 个匹配的备份文件:")
            for url, status_code, size in found_files:
                print(f"[+] {url} (状态码: {status_code}, 大小: {size:,} 字节)")
        else:
            print("\n未发现任何匹配的备份文件")

def read_backup_patterns(file_path='config/bak.txt'):
    """读取备份文件模式列表"""
    patterns = set()
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    patterns.add(line)
    return patterns

def generate_backup_names_from_pattern(url, pattern):
    """根据模式生成备份文件名"""
    # 使用urlparse解析URL
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
    netloc = parsed.netloc or parsed.path.split('/')[0]
    
    # 分割域名部分
    parts = netloc.split('.')
    
    # 替换模式中的变量
    name = pattern
    if len(parts) >= 3:  # 例如 www.baidu.com
        name = name.replace('%a%', parts[0])  # www
        name = name.replace('%b%', parts[1])  # baidu
        name = name.replace('%c%', parts[2])  # com
    elif len(parts) == 2:  # 例如 baidu.com
        name = name.replace('%a%', '')
        name = name.replace('%b%', parts[0])  # baidu
        name = name.replace('%c%', parts[1])  # com
    
    # 如果还有未替换的变量，则跳过这个模式
    if '%a%' in name or '%b%' in name or '%c%' in name:
        return None
        
    return name

def is_ip_address(s):
    # 检查是否是IP地址
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, s):
        return False
    # 验证每个数字是否在0-255范围内
    return all(0 <= int(num) <= 255 for num in s.split('.'))

def process_ip_address(ip):
    # 处理IP地址的各种组合
    base_names = set()
    parts = ip.split('.')
    
    # 原始IP
    base_names.add(ip)
    
    # 下划线连接
    base_names.add('_'.join(parts))
    
    # 直接连接
    base_names.add(''.join(parts))
    
    # 处理不同长度的子段
    for i in range(len(parts)):
        # 从头开始的子段
        front_parts = parts[i:]
        if len(front_parts) > 1:
            base_names.add('.'.join(front_parts))
            base_names.add('_'.join(front_parts))
            base_names.add(''.join(front_parts))
        
        # 从尾部开始的子段
        back_parts = parts[:len(parts)-i]
        if len(back_parts) > 1:
            base_names.add('.'.join(back_parts))
            base_names.add('_'.join(back_parts))
            base_names.add(''.join(back_parts))
    
    return base_names

def process_domain(url):
    # 处理域名的各种组合
    base_names = set()
    parts = url.split('.')
    
    # 原始完整域名
    base_names.add(url)
    
    # 处理多级域名的情况
    if len(parts) > 1:
        # 原始下划线连接
        base_names.add('_'.join(parts))
        
        # 原始直接连接
        base_names.add(''.join(parts))
        
        # 移除www的情况（如果存在）
        if parts[0].lower() == 'www':
            without_www = '.'.join(parts[1:])
            base_names.add(without_www)
            base_names.add('_'.join(parts[1:]))
            base_names.add(''.join(parts[1:]))
        
        # 处理每个部分
        for i in range(len(parts)):
            # 单个部分
            base_names.add(parts[i])
            
            # 相邻两部分的组合
            if i < len(parts) - 1:
                two_parts = f"{parts[i]}.{parts[i+1]}"
                base_names.add(two_parts)
                base_names.add(f"{parts[i]}_{parts[i+1]}")
                base_names.add(f"{parts[i]}{parts[i+1]}")
        
        # 处理去掉最后一个部分的情况
        if len(parts) > 2:
            without_last = '.'.join(parts[:-1])
            base_names.add(without_last)
            base_names.add('_'.join(parts[:-1]))
            base_names.add(''.join(parts[:-1]))
    
    return base_names

def process_url_with_path(url):
    # 使用urlparse解析URL
    parsed = urlparse(url)
    
    # 获取基本域名或IP
    netloc = parsed.netloc or parsed.path.split('/')[0]
    
    # 获取完整路径（不包括查询参数和片段）
    path_parts = [p for p in parsed.path.split('/') if p]
    
    base_names = set()
    
    # 处理基本域名/IP
    if is_ip_address(netloc):
        base_names.update(process_ip_address(netloc))
    else:
        base_names.update(process_domain(netloc))
    
    # 如果有路径，添加带路径的组合
    if path_parts:
        # 获取基本名称（用于后面和路径组合）
        basic_names = base_names.copy()
        
        for base in basic_names:
            # 完整路径组合
            full_path = '_'.join(path_parts)
            base_names.add(f"{base}_{full_path}")
            base_names.add(f"{base}{full_path}")
            
            # 处理每个路径段
            for i in range(len(path_parts)):
                path_segment = path_parts[i]
                base_names.add(f"{base}_{path_segment}")
                base_names.add(f"{base}{path_segment}")
                
                # 相邻路径段组合
                if i < len(path_parts) - 1:
                    next_segment = path_parts[i + 1]
                    combined = f"{path_segment}_{next_segment}"
                    base_names.add(f"{base}_{combined}")
                    base_names.add(f"{base}{combined}")
    
    return base_names

def generate_backup_names(url):
    # 常见的压缩文件扩展名
    extensions = [
        'zip', '7z', 'tar.gz', 'tar.7z', 'rar', 'tar', 'gz', 
        'tar.bz2', 'bz2', 'tar.xz', 'xz', 'tgz'
    ]
    
    # 确保URL有协议前缀，如果没有则添加
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # 使用新的URL处理函数
    base_names = process_url_with_path(url)

    # 生成所有可能的组合
    backup_names = set()  # 使用set避免重复
    
    # 添加基于URL生成的文件名
    for base_name, ext in product(base_names, extensions):
        backup_names.add(f"{base_name}.{ext}")
    
    # 读取并添加bak.txt中的模式
    patterns = read_backup_patterns()
    
    # 添加从bak.txt生成的文件名
    for pattern in patterns:
        # 如果是固定文件名（不包含变量），直接添加
        if '%' not in pattern:
            backup_names.add(pattern)
        else:
            # 如果是带变量的模式，尝试生成
            generated = generate_backup_names_from_pattern(url, pattern)
            if generated:
                backup_names.add(generated)
    
    # 添加一些通用的备份文件名
    common_names = {
        'backup', 'bak', 'back', 'backups', 'beifen', 'web', 'website',
        'www', 'wwwroot', 'data', 'database', 'db', 'sql', 'mysql',
        '1', '2', 'old', 'new', 'tmp', 'temp'
    }
    
    for name in common_names:
        for ext in extensions:
            backup_names.add(f"{name}.{ext}")

    return sorted(backup_names)  # 排序以获得更好的显示效果

def parse_status_codes(status_codes_str: str) -> List[int]:
    """解析状态码参数"""
    try:
        return [int(code.strip()) for code in status_codes_str.split(',')]
    except ValueError:
        raise argparse.ArgumentTypeError('状态码必须是以逗号分隔的整数列表')

def main():
    parser = argparse.ArgumentParser(description='生成可能的备份文件名列表并检测是否存在')
    parser.add_argument('-u', '--url', required=True, help='要处理的URL或IP地址')
    parser.add_argument('-s', '--status-codes', 
                      type=parse_status_codes,
                      default='200,201',
                      help='要检查的HTTP状态码，用逗号分隔（默认：200,201）')
    parser.add_argument('-t', '--threads',
                      type=int,
                      default=10,
                      help='并发线程数（默认：10）')
    parser.add_argument('-T', '--timeout',
                      type=int,
                      default=5,
                      help='请求超时时间（秒）（默认：5）')
    
    args = parser.parse_args()
    
    # 生成所有可能的备份文件名
    backup_names = generate_backup_names(args.url)
    print(f"\n已生成 {len(backup_names)} 个可能的文件名")
    
    # 创建扫描器并开始扫描
    scanner = BackupScanner(args.url, args.status_codes, args.threads, args.timeout)
    scanner.scan_backup_files(set(backup_names))

if __name__ == '__main__':
    main() 