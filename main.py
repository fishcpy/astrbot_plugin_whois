from __future__ import annotations

from datetime import date, datetime
from typing import Any, Iterable

import whois

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register


_FIELD_TRANSLATIONS = {
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


def _format_datetime(value: datetime | date) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value.strftime("%Y-%m-%d")


def _stringify(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return _format_datetime(value)
    if isinstance(value, (list, tuple, set)):
        parts = [_stringify(item) for item in value if item not in (None, "")]
        return ", ".join(parts)
    return str(value)


def _extract_whois_data(result: Any) -> dict[str, Any]:
    if hasattr(result, "items"):
        try:
            return dict(result.items())
        except Exception:  # pragma: no cover - defensive
            pass
    if hasattr(result, "__dict__"):
        return dict(result.__dict__)
    return {}


def _build_reply(data: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, label in _FIELD_TRANSLATIONS.items():
        value = data.get(key)
        if value in (None, "", [], (), set()):
            continue
        text = _stringify(value)
        if not text:
            continue
        lines.append(f"{label}: {text}")
    if not lines:
        return "未获取到有效的 WHOIS 信息。"
    return "\n".join(lines)


def _parse_domain(message: str) -> str | None:
    parts = message.strip().split()
    if not parts:
        return None
    if len(parts) >= 2:
        return parts[1].strip()
    return None


@register(
    "astrbot_plugin_whois",
    "fishcpy",
    "whois查询。",
    "1.0.7",
    "https://github.com/fishcpy/astrbot_plugin_whois",
)
class WhoisPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    @filter.command("whois")
    async def whois_command(self, event: AstrMessageEvent):
        """WHOIS 查询。用法：/whois 域名"""
        event.should_call_llm(False)
        message_str = event.message_str
        domain = _parse_domain(message_str)
        if not domain:
            yield event.plain_result("用法：/whois 域名")
            return

        logger.info("whois query: %s", domain)
        try:
            result = whois.whois(domain)
        except Exception as exc:
            logger.exception("whois query failed: %s", exc)
            yield event.plain_result(f"查询失败：{exc}")
            return

        data = _extract_whois_data(result)
        reply = _build_reply(data)
        yield event.plain_result(reply)

    async def terminate(self):
        """插件卸载/停用时调用。"""
        logger.info("astrbot_plugin_whois terminated")
