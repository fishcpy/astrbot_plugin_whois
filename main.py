from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
import sys
import os
import datetime

# 检查是否存在python-whois模块，如果不存在则尝试自动安装
try:
    import whois as python_whois
except ImportError:
    print("正在尝试自动安装python-whois模块...")
    try:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-whois"])
        import whois as python_whois
        print("python-whois模块安装成功!")
    except Exception as e:
        print(f"自动安装失败: {e}")
        print("请手动执行以下命令安装依赖:")
        print("pip install python-whois")
        # 不直接抛出异常，而是提供更友好的错误信息
        python_whois = None

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

@register("whois", "Fshcpy", "查询域名的 WHOIS 信息", "1.0.6")
class WhoisPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        self.whois_available = python_whois is not None

    async def initialize(self):
        """可选择实现异步的插件初始化方法，当实例化该插件类之后会自动调用该方法。"""
        if not self.whois_available:
            print("警告: python-whois模块未安装，插件功能将受限")
            print("请使用以下命令安装依赖: pip install python-whois")

    @filter.command("whois")
    async def whois_command(self, event: AstrMessageEvent, domain: str = None):
        """查询一个域名的 whois 信息"""

        if not domain:
            # 使用 return 直接返回消息，而不是使用 yield
            return "请提供要查询的域名。用法：/whois <域名>"
            
        if not self.whois_available:
            return "whois模块未安装，无法执行查询。请联系管理员安装python-whois模块。"

        try:
            w = python_whois.whois(domain)
            if w is None:
                return f"无法查询域名 {domain}，请检查域名是否正确。"
                
            if not w.get('domain_name'):
                return f"无法查询到域名 {domain} 的 WHOIS 信息，请检查域名是否正确。"

            whois_info = []
            for key, value in w.items():
                if value is not None and value != "":  # 排除空值
                    key_display = translation_dict.get(key, key)
                    try:
                        if isinstance(value, list):
                            # 过滤掉None和空字符串
                            filtered_values = [str(v) for v in value if v is not None and str(v).strip() != ""]
                            if filtered_values:  # 确保有值才添加
                                value_display = ", ".join(filtered_values)
                                whois_info.append(f"{key_display}: {value_display}")
                        elif isinstance(value, datetime.datetime):
                            value_display = value.strftime("%Y-%m-%d %H:%M:%S")
                            whois_info.append(f"{key_display}: {value_display}")
                        elif str(value).strip():  # 确保非空字符串
                            whois_info.append(f"{key_display}: {str(value)}")
                    except Exception as e:
                        # 跳过处理有问题的字段
                        continue
            
            response = f"域名 {domain} 的 WHOIS 信息：\n" + "\n".join(whois_info)
            return response

        except Exception as e:
            return f"查询域名 {domain} 时发生错误：{e}"

    async def terminate(self):
        """可选择实现异步的插件销毁方法，当插件被卸载/停用时会调用。"""
        pass