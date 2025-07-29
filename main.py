from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
import whois
import datetime

# 创建翻译字典
translation_dict = {
    'domain_name': '域名',
    'registrar': '注册商',
    'whois_server': 'WHOIS服务器',
    'referral_url': '推荐链接',
    'updated_date': '更新日期',
    'creation_date': '创建日期',
    'expiration_date': '到期日期',
    'name_servers': '名称服务器',
    'status': '状态',
    'emails': '邮箱',
    'dnssec': 'DNSSEC',
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

@register("whois", "Fshcpy", "查询域名的 WHOIS 信息", "1.0.1")
class WhoisPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    async def initialize(self):
        """可选择实现异步的插件初始化方法，当实例化该插件类之后会自动调用该方法。"""
        pass

    @filter.command("whois")
    async def whois_command(self, event: AstrMessageEvent, domain: str):
        """查询一个域名的 whois 信息"""

        if not domain:
            yield event.plain_result("请提供要查询的域名。用法：/whois <域名>")
            return

        try:
            w = whois.whois(domain)
            if not w.get('domain_name'):
                yield event.plain_result(f"无法查询到域名 {domain} 的 WHOIS 信息，请检查域名是否正确。")
                return

            whois_info = []
            for key, value in w.items():
                if value:
                    key_display = translation_dict.get(key, key)
                    if isinstance(value, list):
                        value_display = ", ".join(str(v) for v in value)
                        whois_info.append(f"{key_display}: {value_display}")
                    elif isinstance(value, datetime.datetime):
                        value_display = value.strftime("%Y-%m-%d %H:%M:%S")
                        whois_info.append(f"{key_display}: {value_display}")
                    else:
                        whois_info.append(f"{key_display}: {str(value)}")
            
            yield event.plain_result(f"域名 {domain} 的 WHOIS 信息：")
            for info in whois_info:
                yield event.plain_result(info)

        except Exception as e:
            yield event.plain_result(f"查询域名 {domain} 时发生错误：{e}")

    async def terminate(self):
        """可选择实现异步的插件销毁方法，当插件被卸载/停用时会调用。"""
        pass