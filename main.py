import asyncio
from datetime import date, datetime
from typing import Any
from urllib.parse import urlparse

import whois
from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star


FIELD_TRANSLATIONS = {
    "domain_name": "域名",
    "registrar": "注册商",
    "whois_server": "WHOIS服务器",
    "referral_url": "推荐链接",
    "updated_date": "更新日期",
    "creation_date": "创建日期",
    "expiration_date": "到期日期",
    "name_servers": "名称服务器",
    "status": "状态",
    "emails": "邮箱",
    "dnssec": "DNSSEC",
    "name": "姓名",
    "org": "组织",
    "address": "地址",
    "city": "城市",
    "state": "省份",
    "registrant_postal_code": "邮政编码",
    "country": "国家",
    "registrant_name": "注册人姓名",
    "registrant_address": "注册人地址",
    "registrant_phone_number": "注册人电话",
    "registrant_email": "注册人邮箱",
    "admin_email": "管理员邮箱",
    "billing_email": "账单邮箱",
    "tech_email": "技术支持邮箱",
    "domain__id": "域名ID",
    "registrar_id": "注册商ID",
    "registrar_url": "注册商网址",
}


class WhoisPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    @filter.command("whois")
    async def handle_whois(self, event: AstrMessageEvent, args: Any = ""):
        """查询域名 WHOIS 信息。用法: whois example.com"""
        domain_arg = self._get_first_arg(args)
        if not domain_arg:
            yield event.plain_result("请提供要查询的域名，例如: whois example.com")
            return

        domain = self._normalize_domain(domain_arg)
        if not domain:
            yield event.plain_result("域名格式不正确，请输入类似 example.com 的域名。")
            return

        try:
            result = await asyncio.to_thread(whois.whois, domain)
        except Exception as exc:
            logger.warning(f"WHOIS 查询失败: {domain}: {exc}")
            yield event.plain_result(f"查询 {domain} 的 WHOIS 信息失败: {exc}")
            return

        yield event.plain_result(self._format_whois_result(domain, result))

    def _get_first_arg(self, raw_args: Any) -> str:
        if isinstance(raw_args, str):
            parsed_args = raw_args.split()
        elif isinstance(raw_args, (list, tuple)):
            parsed_args = [str(arg) for arg in raw_args if not self._is_empty(arg)]
        elif raw_args:
            parsed_args = [str(raw_args)]
        else:
            parsed_args = []

        return parsed_args[0] if parsed_args else ""

    def _normalize_domain(self, raw_domain: str) -> str:
        domain = raw_domain.strip().lower()
        if not domain:
            return ""

        parsed = urlparse(domain if "://" in domain else f"//{domain}")
        domain = parsed.hostname or domain.split("/")[0]
        domain = domain.strip(".")

        if not domain or " " in domain or "." not in domain:
            return ""
        return domain

    def _format_whois_result(self, domain: str, result: Any) -> str:
        data = self._as_dict(result)
        lines = [f"WHOIS 查询结果: {domain}"]

        for key, label in FIELD_TRANSLATIONS.items():
            value = data.get(key)
            if self._is_empty(value):
                continue
            lines.append(f"{label}: {self._format_value(value)}")

        if len(lines) == 1:
            lines.append("未查询到可展示的 WHOIS 信息。")

        return "\n".join(lines)

    def _as_dict(self, result: Any) -> dict[str, Any]:
        if isinstance(result, dict):
            return result
        if hasattr(result, "items"):
            return dict(result.items())
        return {key: getattr(result, key) for key in FIELD_TRANSLATIONS if hasattr(result, key)}

    def _format_value(self, value: Any) -> str:
        if isinstance(value, (list, tuple, set)):
            items = [self._format_value(item) for item in value if not self._is_empty(item)]
            return ", ".join(dict.fromkeys(items))
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(value, date):
            return value.strftime("%Y-%m-%d")
        return str(value).strip()

    def _is_empty(self, value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            return not value.strip()
        if isinstance(value, (list, tuple, set, dict)):
            return len(value) == 0
        return False
