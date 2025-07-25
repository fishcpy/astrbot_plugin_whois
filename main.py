from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
import whois
import socket

# 创建翻译字典
translation_dict = {
    # 基本域名信息
    'domain_name': '域名',
    'domain': '域名',
    'domain_name_servers': '域名服务器',
    'registrar': '注册商',
    'registrar_name': '注册商名称',
    'whois_server': 'WHOIS服务器',
    'referral_url': '推荐链接',
    'registrar_url': '注册商网址',
    'registrar_id': '注册商ID',
    'registrar_iana_id': '注册商IANA ID',
    
    # 日期信息
    'updated_date': '更新日期',
    'creation_date': '创建日期',
    'expiration_date': '到期日期',
    'registry_expiry_date': '注册局到期日期',
    'registrar_registration_expiration_date': '注册商到期日期',
    'last_updated': '最后更新',
    'last_update': '最后更新',
    'print_date': '打印日期',
    
    # 名称服务器
    'name_servers': '名称服务器（DNS解析）',
    'nserver': '名称服务器',
    'nameserver': '名称服务器',
    'name_server': '名称服务器',
    
    # 状态信息
    'status': '状态',
    'domain_status': '域名状态',
    'registry_domain_status': '注册局域名状态',
    'registrar_domain_status': '注册商域名状态',
    
    # 联系信息
    'emails': '邮箱',
    'email': '邮箱',
    'registrant_email': '注册人邮箱',
    'admin_email': '管理员邮箱',
    'billing_email': '账单邮箱',
    'tech_email': '技术支持邮箱',
    'registrant_name': '注册人姓名',
    'registrant_organization': '注册人组织',
    'registrant_address': '注册人地址',
    'registrant_phone': '注册人电话',
    'registrant_phone_number': '注册人电话',
    'registrant_postal_code': '注册人邮政编码',
    'registrant_city': '注册人城市',
    'registrant_state': '注册人省份',
    'registrant_country': '注册人国家',
    
    # 管理联系人
    'admin_name': '管理员姓名',
    'admin_organization': '管理员组织',
    'admin_address': '管理员地址',
    'admin_phone': '管理员电话',
    'admin_city': '管理员城市',
    'admin_state': '管理员省份',
    'admin_country': '管理员国家',
    
    # 技术联系人
    'tech_name': '技术联系人姓名',
    'tech_organization': '技术联系人组织',
    'tech_address': '技术联系人地址',
    'tech_phone': '技术联系人电话',
    'tech_city': '技术联系人城市',
    'tech_state': '技术联系人省份',
    'tech_country': '技术联系人国家',
    
    # 其他信息
    'dnssec': 'DNSSEC',
    'name': '姓名',
    'org': '组织',
    'organization': '组织',
    'address': '地址',
    'city': '城市',
    'state': '省份',
    'country': '国家',
    'postal_code': '邮政编码',
    'phone': '电话',
    'fax': '传真',
    'domain__id': '域名ID',
    'registry_domain_id': '注册局域名ID',
    'registrar_whois_server': '注册商WHOIS服务器',
    'registrar_abuse_contact_email': '注册商滥用联系邮箱',
    'registrar_abuse_contact_phone': '注册商滥用联系电话',
}

@register("astrbot_plugin_whois", "YourName", "一个域名 WHOIS 查询插件", "1.0.0")
class Main(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    async def initialize(self):
        pass

    def get_whois_server(self, tld):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)  # 设置超时
            s.connect(('whois.iana.org', 43))
            s.send((tld + '\r\n').encode())
            response = b""
            while True:
                data = s.recv(4096)
                response += data
                if not data:
                    break
            s.close()
            resp = response.decode('utf-8', errors='ignore')
            for line in resp.splitlines():
                if line.startswith('whois:'):
                    return line.split(':', 1)[1].strip()
            return None
        except Exception as e:
            logger.error(f"获取WHOIS服务器失败: {e}")
            return None

    @filter.command("whois")
    async def whois_command(self, event: AstrMessageEvent):
        """这是一个 whois 查询指令"""
        parts = event.message_str.strip().split()
        if len(parts) < 2:
            yield event.plain_result("请提供要查询的域名")
            return
        domain = parts[1]  # 第二个参数才是域名，第一个是命令名

        try:
            # 首先尝试使用python-whois库
            result = whois.whois(domain)
            logger.info(f"python-whois结果类型: {type(result)}, 内容: {result}")
            
            # 检查python-whois是否返回有效结果
            whois_success = False
            if result:
                if hasattr(result, '__dict__'):
                    # 如果是对象，转换为字典
                    result_dict = {k: v for k, v in result.__dict__.items() if v is not None and str(v).strip()}
                    if result_dict:
                        result = result_dict
                        whois_success = True
                elif isinstance(result, dict):
                    # 如果已经是字典，检查是否有有效内容
                    if any(v for v in result.values() if v is not None and str(v).strip()):
                        whois_success = True
            
            # 如果python-whois失败，尝试手动查询
            if not whois_success:
                logger.info(f"python-whois未返回有效结果，尝试手动查询域名: {domain}")
                tld = domain.split('.')[-1]
                server = self.get_whois_server(tld)
                logger.info(f"获取到WHOIS服务器: {server}")
                
                if server:
                    raw = manual_whois(domain, server)
                    logger.info(f"手动查询原始结果: {raw[:200]}...")
                    result = {}
                    for line in raw.splitlines():
                        line = line.strip()
                        if ':' in line and not line.startswith('%') and not line.startswith('#') and not line.startswith('>>>') and not line.startswith('For more information'):
                            # 处理包含冒号的行
                            parts_line = line.split(':', 1)
                            if len(parts_line) == 2:
                                key, value = parts_line
                                key = key.strip().lower()
                                value = value.strip()
                                
                                # 清理键名，移除特殊字符
                                key = key.replace(' ', '_').replace('-', '_').replace('/', '_')
                                
                                # 过滤掉无用的值
                                if value and value != 'REDACTED FOR PRIVACY' and not value.startswith('Please query') and not value.startswith('Select Contact'):
                                    result[key] = value

            if result and isinstance(result, dict):
                # 过滤掉空值和无用信息
                filtered_result = {k: v for k, v in result.items() if v and str(v).strip() and str(v).strip() != 'None'}
                
                if filtered_result:
                    whois_info = []
                    for key, value in filtered_result.items():
                        if value:
                            # 获取翻译后的键名
                            translated_key = translation_dict.get(key, key)
                            # 如果是列表，转换为字符串
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value if v)
                            whois_info.append(f"{translated_key}: {value}")
                    
                    if whois_info:
                        response = f"域名信息 ({domain}):\n" + "\n".join(whois_info)
                    else:
                        response = f"无法获取域名 {domain} 的详细信息，可能需要手动查询。"
                else:
                    response = f"无法获取域名 {domain} 的详细信息，可能需要手动查询。"
            else:
                response = f"无法获取域名 {domain} 的信息"
                
        except Exception as e:
            logger.error(f"查询域名 {domain} 时出错: {e}")
            response = f"查询域名 {domain} 信息时出错: {e}"

        response += "\n\n插件 BY FishCpy, 翻译 BY AcoFork"

        yield event.plain_result(response)

    async def terminate(self):
        pass

def manual_whois(domain, server):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 43))
    s.send((domain + '\r\n').encode())
    response = b""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    return response.decode('utf-8', errors='ignore')
