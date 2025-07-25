from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
import whois
import socket

# 创建翻译字典
translation_dict = {
    'domain_name': '域名',
    'domain': '域名',
    'registrar': '注册商',
    'whois_server': 'WHOIS服务器',
    'referral_url': '推荐链接',
    'updated_date': '更新日期',
    'creation_date': '创建日期',
    'expiration_date': '到期日期',
    'name_servers': '名称服务器（DNS解析）',
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
    # 添加更多常见的字段名
    'registry_domain_id': '注册域名ID',
    'registrar_whois_server': '注册商WHOIS服务器',
    'registrar_url': '注册商网址',
    'updated_date': '更新日期',
    'creation_date': '创建日期',
    'registry_expiry_date': '注册到期日期',
    'registrar': '注册商',
    'registrar_iana_id': '注册商IANA ID',
    'registrar_abuse_contact_email': '注册商滥用联系邮箱',
    'registrar_abuse_contact_phone': '注册商滥用联系电话',
    'domain_status': '域名状态',
    'name_server': '名称服务器',
    'dnssec': 'DNSSEC',
    'url_of_the_icann_whois_inaccuracy_complaint_form': 'ICANN WHOIS投诉表单',
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
                        if ':' in line and not line.strip().startswith('%') and not line.strip().startswith('#'):
                            key, value = line.split(':', 1)
                            key = key.strip().lower().replace(' ', '_').replace('-', '_')
                            value = value.strip()
                            if value:  # 只保存非空值
                                result[key] = value

            if result and isinstance(result, dict):
                # 过滤掉空值和无用信息
                filtered_result = {k: v for k, v in result.items() if v and str(v).strip() and str(v).strip() != 'None'}
                
                if filtered_result:
                    whois_info_lines = []
                    for key, value in filtered_result.items():
                        if value:
                            # 尝试多种方式匹配翻译
                            translated_key = None
                            
                            # 1. 直接匹配
                            if key in translation_dict:
                                translated_key = translation_dict[key]
                            # 2. 转换为小写后匹配
                            elif key.lower() in translation_dict:
                                translated_key = translation_dict[key.lower()]
                            # 3. 替换下划线为空格后匹配
                            elif key.replace('_', ' ') in translation_dict:
                                translated_key = translation_dict[key.replace('_', ' ')]
                            # 4. 替换下划线为空格并转小写后匹配
                            elif key.replace('_', ' ').lower() in translation_dict:
                                translated_key = translation_dict[key.replace('_', ' ').lower()]
                            
                            # 如果找到翻译，使用翻译；否则使用原始键名
                            display_key = translated_key if translated_key else key
                            
                            # 处理列表类型的值
                            if isinstance(value, list):
                                value_str = ', '.join(str(v) for v in value if v)
                            else:
                                value_str = str(value)
                            
                            if value_str:
                                whois_info_lines.append(f"{display_key}: {value_str}")
                    
                    whois_info = "\n".join(whois_info_lines)
                    if whois_info:
                        response = f"域名信息 ({domain}):\n{whois_info}"
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
