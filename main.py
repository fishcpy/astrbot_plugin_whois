from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

@register("helloworld", "YourName", "一个简单的 Hello World 插件", "1.0.0")
class MyPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    async def initialize(self):
        """可选择实现异步的插件初始化方法，当实例化该插件类之后会自动调用该方法。"""
    
    # 注册指令的装饰器。指令名为 helloworld。注册成功后，发送 `/helloworld` 就会触发这个指令，并回复 `你好, {user_name}!`
    @filter.command("helloworld")
    async def helloworld(self, event: AstrMessageEvent):
        """这是一个 hello world 指令""" # 这是 handler 的描述，将会被解析方便用户了解插件内容。建议填写。
        user_name = event.get_sender_name()
        message_str = event.message_str # 用户发的纯文本消息字符串
        message_chain = event.get_messages() # 用户所发的消息的消息链 # from astrbot.api.message_components import *
        logger.info(message_chain)
        yield event.plain_result(f"Hello, {user_name}, 你发了 {message_str}!") # 发送一条纯文本消息

    async def terminate(self):
        """可选择实现异步的插件销毁方法，当插件被卸载/停用时会调用。"""

@register("whois", "YourName", "域名 Whois 查询插件", "1.0.0")
class WhoisPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        # 翻译字典
        self.translation_dict = {
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

    async def initialize(self):
        pass

    @filter.command("whois")
    async def whois_query(self, event: AstrMessageEvent):
        """查询域名 Whois 信息"""
        import whois
        domain = event.message_str.strip()
        if not domain:
            yield event.plain_result("请提供要查询的域名")
            return
        try:
            result = whois.whois(domain)
            if result:
                info_lines = [
                    f"{self.translation_dict.get(key, key)}: {value}"
                    for key, value in result.items() if value
                ]
                if info_lines:
                    whois_info = "\n".join(info_lines)
                    response = f"域名信息 ({domain}):\n{whois_info}"
                else:
                    response = f"域名 {domain} 没有详细信息。"
            else:
                response = f"无法获取域名 {domain} 的信息"
        except Exception as e:
            response = f"查询域名 {domain} 信息时出错: {e}"
        yield event.plain_result(response)