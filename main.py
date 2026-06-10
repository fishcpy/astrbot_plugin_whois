import asyncio
import json
from datetime import date, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
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

ERROR_TRANSLATIONS = {
    "Whois command returned no output": "WHOIS 命令没有返回任何结果，可能是该域名不支持传统 WHOIS 查询、查询服务暂时不可用，或已被服务器限制。",
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

        message, errors = await self._query_fastest(domain)
        if not message:
            error_text = "\n".join(errors) if errors else "请稍后重试。"
            yield event.plain_result(f"查询 {domain} 的 WHOIS/RDAP 信息失败：\n{error_text}")
            return

        yield event.plain_result(message)

    async def _query_fastest(self, domain: str) -> tuple[str, list[str]]:
        tasks = [
            asyncio.create_task(self._query_whois(domain)),
            asyncio.create_task(self._query_rdap(domain)),
        ]
        errors = []

        try:
            for task in asyncio.as_completed(tasks):
                message, error = await task
                if message:
                    return message, errors
                if error:
                    errors.append(error)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

        return "", errors

    async def _query_whois(self, domain: str) -> tuple[str, str]:
        try:
            result = await asyncio.to_thread(whois.whois, domain)
            return self._format_whois_result(domain, result), ""
        except Exception as exc:
            logger.warning(f"WHOIS 查询失败: {domain}: {exc}")
            return "", self._format_query_error("WHOIS", domain, exc)

    async def _query_rdap(self, domain: str) -> tuple[str, str]:
        try:
            result = await asyncio.to_thread(self._fetch_rdap, domain)
            return self._format_rdap_result(domain, result), ""
        except Exception as exc:
            logger.warning(f"RDAP 查询失败: {domain}: {exc}")
            return "", self._format_query_error("RDAP", domain, exc)

    def _format_query_error(self, source: str, domain: str, exc: Exception) -> str:
        message = str(exc)
        translation = self._translate_error(message)
        if translation:
            message = f"{message}（{translation}）"
        return f"{source}: 查询 {domain} 失败: {message}"

    def _translate_error(self, message: str) -> str:
        for original, translated in ERROR_TRANSLATIONS.items():
            if original in message:
                return translated
        return ""

    def _fetch_rdap(self, domain: str) -> dict[str, Any]:
        url = f"https://rdap.org/domain/{domain}"
        request = Request(url, headers={"User-Agent": "astrbot-plugin-whois/1.0.1"})
        try:
            with urlopen(request, timeout=12) as response:
                body = response.read().decode("utf-8", errors="replace")
                return json.loads(body)
        except HTTPError as exc:
            raise RuntimeError(f"RDAP HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError(f"RDAP 网络错误: {exc.reason}") from exc

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
            return ""

        return "\n".join(lines)

    def _format_rdap_result(self, domain: str, data: dict[str, Any]) -> str:
        lines = [f"RDAP 查询结果: {domain}"]
        field_values = {
            "域名": data.get("ldhName") or data.get("unicodeName"),
            "域名ID": data.get("handle"),
            "状态": data.get("status"),
            "名称服务器": [server.get("ldhName") for server in data.get("nameservers", [])],
            "DNSSEC": data.get("secureDNS", {}).get("delegationSigned"),
            "注册商": self._extract_registrar(data),
            "注册人邮箱": self._extract_public_emails(data),
            "链接": [link.get("href") for link in data.get("links", []) if link.get("href")],
        }

        field_values.update(self._extract_rdap_events(data))

        for label, value in field_values.items():
            if self._is_empty(value):
                continue
            lines.append(f"{label}: {self._format_value(value)}")

        if len(lines) == 1:
            return ""

        return "\n".join(lines)

    def _extract_rdap_events(self, data: dict[str, Any]) -> dict[str, Any]:
        event_labels = {
            "registration": "创建日期",
            "last changed": "更新日期",
            "expiration": "到期日期",
        }
        events = {}
        for event in data.get("events", []):
            label = event_labels.get(event.get("eventAction"))
            if label and event.get("eventDate"):
                events[label] = event.get("eventDate")
        return events

    def _extract_registrar(self, data: dict[str, Any]) -> str:
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" not in roles:
                continue
            vcard = entity.get("vcardArray", [])
            if len(vcard) < 2:
                return entity.get("handle", "")
            for item in vcard[1]:
                if item and item[0] == "fn" and len(item) >= 4:
                    return item[3]
            return entity.get("handle", "")
        return ""

    def _extract_public_emails(self, data: dict[str, Any]) -> list[str]:
        emails = []
        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) < 2:
                continue
            for item in vcard[1]:
                if item and item[0] == "email" and len(item) >= 4:
                    emails.append(item[3])
        return emails

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
