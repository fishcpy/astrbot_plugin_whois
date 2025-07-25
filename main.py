from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
import whois
import socket

# 创建翻译字典
translation_dict = {
    'domain_name': '域名',
    'registrar': '注册商',
    'whois_server': 'WHOIS服务器',
    'referral_url': '推荐链接',
    'updated_date': '更新日期',
    'creation_date': '创建日期',
    'expiration_date': '到期日期',
    'name_servers': '名称服务器（DS解析）',
    'status': '状态',
    'emails': '邮箱',
    'dnssec': 'DNSSEC',
    'print_date': '打印日期',
    'last_update': '最后更新',
    'name': '姓名',
    'org': '组织',
    'address': '地址',
    'city': '城市',
    'state': '省份',
    'registrant_postal_code': '邮政编码',
    'country': '国家',
    'registrant_name': '注册人姓名',
    'registrant_address': '注册人地址',
    'registrant_phone_number': '注册人电话',
    'registrant_email': '注册人邮箱',
    'admin_email': '管理员邮箱',
    'billing_email': '账单邮箱',
    'tech_email': '技术支持邮箱',
    'domain__id': '域名ID',
    'registrar_id': '注册商ID',
    'registrar_url': '注册商网址',
}

@register("whois_plugin", "YourName", "一个域名 WHOIS 查询插件", "1.0.0")
class Main(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    async def initialize(self):
        pass

    
    @staticmethod
    def get_whois_server(tld):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

    @filter.command("whois")
    async def whois_command(self, event: AstrMessageEvent, *args, **kwargs):
        """这是一个 whois 查询指令"""
        parts = event.message_str.strip().split()
        if len(parts) < 1:
            yield event.plain_result("请提供要查询的域名")
            return
        domain = parts[0]  # 假设命令后直接跟域名
    
        try:
            # 尝试获取域名信息
            raw = ''
            result = whois.whois(domain)
            if result and hasattr(result, 'text'):
                raw = result.text
            if not result:
                tld = domain.split('.')[-1]
                server = self.get_whois_server(tld)
                if server:
                    raw = manual_whois(domain, server)
                    result = {}
                    for line in raw.splitlines():
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip().lower().replace(' ', '_')
                            value = value.strip()
                            result[key] = value
    
            whois_info = "\n".join(
            f"{translation_dict.get(key, key)}: {value}"
            for key, value in result.items() if value
        ) if result else ""
        if whois_info:
            response = f"域名信息 ({domain}):\n{whois_info}"
        else:
            response = f"无法获取解析的域名信息 ({domain})，但以下是原始WHOIS数据:\n{raw}" if raw else f"无法获取域名 {domain} 的信息"
        except (whois.parser.PywhoisError, socket.error, ConnectionError, TimeoutError, Exception) as e:
            response = f"查询域名 {domain} 信息时出错: {e}"
    
        response += "\n\n插件 BY Fishcpy, 翻译 BY AcoFork"

        response += "\n\n开源于https://github.com/fishcpy/astrbot_plugin_whois"
        
        response += "\n\n由克劳德4在2小时内完成主要开发及BUG修复"

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
