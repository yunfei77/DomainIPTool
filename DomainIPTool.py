import whois
import dns.resolver
import socket
import requests
from datetime import datetime
from colorama import Fore, Style, init
import time
import re

# 初始化colorama
init(autoreset=True)

class DomainIPTool:
    def __init__(self):
        # VirusTotal API 密钥
        self.vt_api_key = "key"  #需要向vt申请
        
        # DNS解析器设置
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    # ========== IP 查询功能 ==========
    
    def vt_ip_reverse_lookup(self, ip_address):
        """使用 VirusTotal API 查询 IP 对应的域名"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/resolutions"
        headers = {
            "x-apikey": self.vt_api_key
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            domains = []

            # 提取所有域名
            for item in data.get("data", []):
                attributes = item.get("attributes", {})
                domain = attributes.get("host_name")
                if domain:
                    domains.append(domain)

            return domains
        elif response.status_code == 403:
            raise Exception("Error: Invalid or missing API key (Permission denied)")
        elif response.status_code == 404:
            raise Exception("Error: IP not found in VirusTotal database")
        else:
            raise Exception(f"HTTP Error {response.status_code}: {response.text}")
    
    # ========== 域名查询功能 ==========
    
    def vt_domain_lookup(self, domain):
        """使用 VirusTotal API 查询域名对应的 IP"""
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
        headers = {
            "x-apikey": self.vt_api_key
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            ip_addresses = []

            # 遍历所有解析记录，提取IP地址
            for item in data.get("data", []):
                attributes = item.get("attributes", {})
                ip_address = attributes.get("ip_address")
                if ip_address:
                    ip_addresses.append(ip_address)

            return ip_addresses
        elif response.status_code == 404:
            print(f"{Fore.YELLOW}警告: 域名 {domain} 在 VirusTotal 数据库中未找到。{Style.RESET_ALL}")
            return []
        else:
            print(f"{Fore.YELLOW}警告: HTTP 错误 {response.status_code}: {response.text}{Style.RESET_ALL}")
            return []
    
    def format_date(self, date_value):
        """格式化日期显示"""
        try:
            if not date_value:
                return '未知'
            
            # 如果是列表，取最早的日期
            if isinstance(date_value, list):
                valid_dates = [d for d in date_value if d]
                if not valid_dates:
                    return '未知'
                date_value = min(valid_dates)  # 取最早的日期
        
            # 如果是datetime对象，格式化显示
            if isinstance(date_value, datetime):
                return date_value.strftime('%Y-%m-%d')  # 只显示日期部分
            
            return str(date_value)
        except Exception as e:
            return f'未知 ({str(e)})'

    def get_whois_info(self, domain):
        """获取域名的WHOIS信息"""
        try:
            # 获取WHOIS信息
            w = whois.whois(domain)
            if not w or not w.domain_name:
                return {'error': '无法获取WHOIS信息'}

            # 处理注册商
            registrar = '未知'
            if hasattr(w, 'registrar') and w.registrar:
                registrar = w.registrar[0] if isinstance(w.registrar, list) else w.registrar

            # 处理日期的辅助函数
            def parse_date(date_value):
                """解析日期，处理时区问题"""
                if not date_value:
                    return None
                if isinstance(date_value, list):
                    # 过滤掉None值
                    dates = [d for d in date_value if d]
                    if not dates:
                        return None
                    # 取第一个日期
                    date_value = dates[0]
                try:
                    if isinstance(date_value, datetime):
                        return date_value.strftime('%Y-%m-%d')
                    return str(date_value).split()[0]  # 只取日期部分
                except:
                    return '未知'

            # 处理各种日期
            creation_date = parse_date(w.creation_date)
            expiration_date = parse_date(w.expiration_date)
            updated_date = parse_date(w.updated_date)

            # 处理状态
            status = set()
            if hasattr(w, 'status') and w.status:
                if isinstance(w.status, list):
                    for s in w.status:
                        if s:
                            # 只保留状态码部分，去除URL和括号
                            s = str(s).split('https://')[0].strip()
                            s = s.split('(')[0].strip()
                            if s:
                                status.add(s)
                else:
                    s = str(w.status).split('https://')[0].strip()
                    s = s.split('(')[0].strip()
                    if s:
                        status.add(s)

            # 处理域名服务器
            nameservers = set()
            if hasattr(w, 'name_servers') and w.name_servers:
                if isinstance(w.name_servers, list):
                    nameservers = {ns.lower() for ns in w.name_servers if ns}
                else:
                    nameservers = {w.name_servers.lower()}

            return {
                'registrar': registrar,
                'creation_date': creation_date or '未知',
                'expiration_date': expiration_date or '未知',
                'last_updated': updated_date or '未知',
                'status': '\n    '.join(sorted(status)) if status else '未知',
                'name_servers': '\n    '.join(sorted(nameservers)) if nameservers else '未知'
            }

        except Exception as e:
            return {'error': f'WHOIS查询失败: {str(e)}'}

    def get_dns_records(self, domain):
        """获取域名的DNS记录"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception:
                continue
        
        return records

    def check_ssl(self, domain):
        """检查域名的SSL证书状态"""
        try:
            response = requests.get(f'https://{domain}', timeout=5, verify=True)
            return {'status': 'Valid SSL', 'code': response.status_code}
        except requests.exceptions.SSLError:
            return {'status': 'Invalid SSL', 'code': None}
        except requests.exceptions.ConnectionError as e:
            if 'NameResolutionError' in str(e):
                return {'status': '域名无法解析', 'code': None}
            elif 'Connection refused' in str(e):
                return {'status': '连接被拒绝', 'code': None}
            else:
                return {'status': '连接错误', 'code': None}
        except requests.exceptions.Timeout:
            return {'status': '连接超时', 'code': None}
        except Exception as e:
            return {'status': f'检查失败', 'code': None}

    def get_main_domain(self, domain):
        """提取主域名（去除www前缀）"""
        if domain.startswith('www.'):
            return domain[4:]
        return domain

    def analyze_domain(self, domain):
        """分析域名的所有信息"""
        print(f"\n{Fore.CYAN}正在检测域名: {domain}{Style.RESET_ALL}")
        
        # 获取主域名用于WHOIS查询
        main_domain = self.get_main_domain(domain)
        
        print("获取WHOIS信息...")
        whois_info = self.get_whois_info(main_domain)  # 使用主域名查询WHOIS
        
        print("获取DNS记录...")
        dns_records = self.get_dns_records(domain)  # 使用原始域名查询DNS
        
        print("检查SSL状态...")
        ssl_info = self.check_ssl(domain)  # 使用原始域名检查SSL
        
        # 记录 IP 地址信息的来源
        ip_source = 'virustotal'

        # 先尝试使用完整域名查询 VirusTotal
        print("查询域名对应的IP地址(VirusTotal)...")
        ip_addresses = self.vt_domain_lookup(domain)

        # 如果完整域名没有结果，且与主域名不同，则尝试使用主域名查询
        if not ip_addresses and domain != main_domain:
            print(f"尝试使用主域名 {main_domain} 查询...")
            ip_addresses = self.vt_domain_lookup(main_domain)

        # 如果 VirusTotal 查询都没有结果，使用 DNS A 记录作为备选
        if not ip_addresses and 'A' in dns_records:
            print("使用 DNS A 记录作为 IP 地址信息...")
            ip_addresses = dns_records['A']
            ip_source = 'dns'  # 更新来源信息

        # 返回结果中添加 IP 来源信息
        return {
            'domain': domain,
            'main_domain': main_domain,
            'whois': whois_info,
            'dns': dns_records,
            'ssl': ssl_info,
            'ip_addresses': ip_addresses,
            'ip_source': ip_source  # 添加来源信息
        }


    def display_domain_results(self, result):
        """显示域名检测结果"""
        print("\n" + "=" * 50)
        print(f"{Fore.CYAN}域名检测报告{Style.RESET_ALL}")
        print("=" * 50)
        
        print(f"\n检测域名: {result['domain']}")
        if result['domain'] != result['main_domain']:
            print(f"主域名: {result['main_domain']}")
        print("-" * 30)
        
        # WHOIS信息
        print(f"\n{Fore.CYAN}WHOIS信息:{Style.RESET_ALL}")
        if 'error' in result['whois']:
            print(f"  {Fore.RED}错误: {result['whois']['error']}{Style.RESET_ALL}")
        else:
            whois_info = result['whois']
            print(f"  注册商: {whois_info['registrar']}")
            print(f"  创建时间: {whois_info['creation_date']}")
            print(f"  到期时间: {whois_info['expiration_date']}")
            print(f"  最后更新: {whois_info['last_updated']}")
            if whois_info['status'] != '未知':
                print(f"  状态: \n    {whois_info['status']}")
            else:
                print(f"  状态: {whois_info['status']}")
            if whois_info['name_servers'] != '未知':
                print(f"  域名服务器: \n    {whois_info['name_servers']}")
            else:
                print(f"  域名服务器: {whois_info['name_servers']}")
        
        # DNS记录
        print(f"\n{Fore.CYAN}DNS记录:{Style.RESET_ALL}")
        if result['dns']:
            for record_type, records in result['dns'].items():
                print(f"  {record_type}记录:")
                for record in records:
                    print(f"    - {record}")
        else:
            print(f"  {Fore.YELLOW}未找到DNS记录{Style.RESET_ALL}")
        
        # SSL状态
        print(f"\n{Fore.CYAN}SSL状态:{Style.RESET_ALL}")
        ssl_status = result['ssl']['status']
        if ssl_status == 'Valid SSL':
            print(f"  {Fore.GREEN}{ssl_status}{Style.RESET_ALL}")
        elif ssl_status in ['域名无法解析', '连接被拒绝', '连接超时', '连接错误', '检查失败']:
            print(f"  {Fore.YELLOW}{ssl_status}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}{ssl_status}{Style.RESET_ALL}")
        if result['ssl']['code']:
            print(f"  HTTP状态码: {result['ssl']['code']}")
        
        # IP地址信息
        print(f"\n{Fore.CYAN}IP地址信息:{Style.RESET_ALL}")
        if result['ip_addresses']:
            print(f"  找到 {len(result['ip_addresses'])} 个关联IP地址:")
            # 添加信息来源说明
            if result.get('ip_source') == 'dns':
                print(f"  {Fore.YELLOW}(来源: DNS A 记录){Style.RESET_ALL}")
            else:
                print(f"  {Fore.YELLOW}(来源: VirusTotal API){Style.RESET_ALL}")
            
            for i, ip in enumerate(result['ip_addresses'], 1):
                print(f"    {i}. {ip}")
        else:
            print(f"  {Fore.YELLOW}未找到关联IP地址{Style.RESET_ALL}")


    def display_ip_results(self, ip_address, domains):
        """显示IP反查域名结果"""
        print("\n" + "=" * 50)
        print(f"{Fore.CYAN}IP反查域名报告{Style.RESET_ALL}")
        print("=" * 50)
        
        print(f"\n查询IP: {ip_address}")
        print("-" * 30)
        
        if domains:
            print(f"\n{Fore.CYAN}找到 {len(domains)} 个关联域名:{Style.RESET_ALL}")
            for i, domain in enumerate(domains[:100], 1):  # 只显示前100个
                print(f"    {i}. {domain}")
        else:
            print(f"\n{Fore.YELLOW}未找到关联域名{Style.RESET_ALL}")

    def extract_domain_from_url(self, url):
        """从URL中提取域名"""
        try:
            # 移除协议部分
            if '://' in url:
                url = url.split('://', 1)[1]
            
            # 移除路径、查询参数和锚点
            url = url.split('/')[0]
            url = url.split('?')[0]
            url = url.split('#')[0]
            
            # 移除端口号
            if ':' in url:
                url = url.split(':')[0]
            
            # 移除用户名和密码部分
            if '@' in url:
                url = url.split('@')[1]
            
            return url.strip().lower()
        except Exception:
            return None

    def is_valid_domain(self, domain):
        """验证域名格式"""
        if not domain:
            return False
        
        # 基本域名格式验证
        if len(domain) > 255:
            return False
        
        # 检查域名部分
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not all(c.isalnum() or c == '-' for c in part):
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
        
        return True

    def is_ip_address(self, input_string):
        """判断输入是否为IP地址"""
        # 使用正则表达式匹配IP地址格式
        ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(ip_pattern, input_string)
        
        if not match:
            return False
        
        # 验证每个部分是否在0-255范围内
        for i in range(1, 5):
            num = int(match.group(i))
            if num < 0 or num > 255:
                return False
        
        return True

    def run(self):
        """运行域名和IP查询工具"""
        try:
            print(f"{Fore.CYAN}域名和IP查询工具{Style.RESET_ALL}")
            print("=" * 50)
            print("功能说明:")
            print("1. 输入域名或URL: 查询域名信息和对应的IP地址")
            print("2. 输入IP地址: 查询IP对应的所有域名")
            print("输入 'exit' 退出程序\n")

            while True:
                try:
                    user_input = input("\n请输入域名、URL或IP地址: ").strip().lower()
                    
                    if user_input == 'exit':
                        print("程序退出")
                        break
                    
                    if not user_input:
                        print(f"{Fore.RED}输入不能为空{Style.RESET_ALL}")
                        continue

                    start_time = time.time()
                    
                    # 判断输入是IP地址还是域名/URL
                    if self.is_ip_address(user_input):
                        # 输入是IP地址，查询对应的域名
                        print(f"{Fore.CYAN}[+] 检测到IP地址输入: {user_input}{Style.RESET_ALL}")
                        print(f"正在查询IP对应的域名...")
                        try:
                            domains = self.vt_ip_reverse_lookup(user_input)
                            self.display_ip_results(user_input, domains)
                        except Exception as e:
                            print(f"{Fore.RED}查询失败: {str(e)}{Style.RESET_ALL}")
                    else:
                        # 输入是域名或URL，提取域名并查询信息
                        domain = self.extract_domain_from_url(user_input)
                        if not domain:
                            print(f"{Fore.RED}无法从输入中提取有效域名{Style.RESET_ALL}")
                            continue

                        # 验证域名格式
                        if not self.is_valid_domain(domain):
                            print(f"{Fore.RED}无效的域名格式{Style.RESET_ALL}")
                            continue

                        # 如果输入的是URL，显示提取的域名
                        if domain != user_input:
                            print(f"{Fore.YELLOW}从URL中提取的域名: {domain}{Style.RESET_ALL}")

                        # 分析域名信息
                        result = self.analyze_domain(domain)
                        self.display_domain_results(result)
                    
                    end_time = time.time()
                    print(f"\n查询耗时: {end_time - start_time:.2f}秒")

                except KeyboardInterrupt:
                    print("\n程序被用户中断")
                    break
                except Exception as e:
                    print(f"{Fore.RED}查询出错: {str(e)}{Style.RESET_ALL}")
                    continue

        except KeyboardInterrupt:
            print("\n程序被用户中断")
        except Exception as e:
            print(f"{Fore.RED}程序运行错误: {str(e)}{Style.RESET_ALL}")
        finally:
            print("\n感谢使用域名和IP查询工具")

if __name__ == "__main__":
    tool = DomainIPTool()
    tool.run()
