from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import re
import ssl
from typing import Iterable
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin
from urllib.request import HTTPCookieProcessor, Request, build_opener
import xml.etree.ElementTree as ET


@dataclass
class HttpResponse:
    status: int
    url: str
    headers: dict[str, str]
    text: str


@dataclass
class LoginResult:
    status: str
    messages: list[str] = field(default_factory=list)
    cookie_names: list[str] = field(default_factory=list)
    cookie_value: str | None = None
    config: "VpnConfig | None" = None

    @property
    def ok(self) -> bool:
        return self.status == "authenticated"


@dataclass
class VpnConfig:
    platform: str = ""
    dtls_enabled: bool = False
    assigned_ipv4: list[str] = field(default_factory=list)
    assigned_ipv6: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    search_domains: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    exclude_routes: list[str] = field(default_factory=list)
    idle_timeout_minutes: int | None = None
    auth_timeout_seconds: int | None = None
    reconnect_without_reauth: bool | None = None


class HiddenFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.fields: dict[str, str] = {}
        self.password_name: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        values = {k.lower(): v or "" for k, v in attrs}
        name = values.get("name")
        if not name:
            return
        input_type = values.get("type", "").lower()
        if input_type == "hidden":
            self.fields[name] = values.get("value", "")
        elif input_type in {"password", "text"} and self.password_name is None:
            self.password_name = name


class FortinetClient:
    def __init__(
        self,
        base_url: str,
        *,
        verify_tls: bool = True,
        user_agent: str = "Mozilla/5.0 SV1",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.cookies = CookieJar()
        self.user_agent = user_agent

        handlers = [HTTPCookieProcessor(self.cookies)]
        if not verify_tls:
            context = ssl._create_unverified_context()
            from urllib.request import HTTPSHandler

            handlers.append(HTTPSHandler(context=context))
        self.opener = build_opener(*handlers)

    def probe(self) -> HttpResponse:
        return self.get("remote/login")

    def login(
        self,
        username: str,
        password: str,
        *,
        realm: str = "",
        mfa_code: str | None = None,
        blank_mfa: bool = False,
        max_challenges: int = 3,
        fetch_config: bool = True,
        show_cookie_value: bool = False,
        on_event=None,
    ) -> LoginResult:
        messages: list[str] = []
        login_path = "remote/login" + (f"?realm={realm}" if realm else "")
        login_page = self.get(login_path)
        if on_event:
            on_event("login_http", method="GET", path="remote/login", status=login_page.status, response=classify_login_response(login_page.text), cookies=self.cookie_names())

        response = self.post_form(
            "remote/logincheck",
            {
                "username": username,
                "credential": password,
                "realm": realm,
                "ajax": "1",
                "just_logged_in": "1",
                "redir": "/remote/index",
            },
        )
        if on_event:
            on_event("login_http", method="POST", path="remote/logincheck", status=response.status, response=classify_login_response(response.text), cookies=self.cookie_names(), request="initial-credentials")
        message = f"initial logincheck returned HTTP {response.status}"
        messages.append(message)
        if on_event:
            on_event("login_note", message=message)

        for challenge_index in range(max_challenges + 1):
            cookie = self._svpncookie()
            if cookie:
                config = self.fetch_config() if fetch_config else None
                return LoginResult(
                    status="authenticated",
                    messages=messages,
                    cookie_names=self.cookie_names(),
                    cookie_value=cookie if show_cookie_value else None,
                    config=config,
                )

            token_fields = parse_tokeninfo(response.text)
            if token_fields:
                if challenge_index >= max_challenges:
                    break
                message = "received tokeninfo MFA challenge"
                messages.append(message)
                if on_event:
                    on_event("login_note", message=message)
                response = self.post_form(
                    "remote/logincheck",
                    build_tokeninfo_response(
                        username=username,
                        realm=realm,
                        token_fields=token_fields,
                        mfa_code=mfa_code,
                        blank_mfa=blank_mfa,
                    ),
                )
                if on_event:
                    on_event("login_http", method="POST", path="remote/logincheck", status=response.status, response=classify_login_response(response.text), cookies=self.cookie_names(), request="mfa-response")
                message = f"MFA logincheck returned HTTP {response.status}"
                messages.append(message)
                if on_event:
                    on_event("login_note", message=message)
                continue

            html_fields = parse_html_form(response.text)
            if html_fields:
                if challenge_index >= max_challenges:
                    break
                message = "received HTML MFA challenge"
                messages.append(message)
                if on_event:
                    on_event("login_note", message=message)
                credential = "" if blank_mfa else (mfa_code or "")
                html_fields.setdefault("username", username)
                html_fields[html_fields.pop("_password_name", "credential")] = credential
                response = self.post_form("remote/logincheck", html_fields)
                if on_event:
                    on_event("login_http", method="POST", path="remote/logincheck", status=response.status, response=classify_login_response(response.text), cookies=self.cookie_names(), request="html-mfa-response")
                message = f"HTML MFA logincheck returned HTTP {response.status}"
                messages.append(message)
                if on_event:
                    on_event("login_note", message=message)
                continue

            if response.status == 405:
                return LoginResult("invalid-credentials", messages, self.cookie_names())

            if looks_like_login_page(response.text):
                return LoginResult("authentication-required", messages, self.cookie_names())

            break

        messages.append("no SVPNCOOKIE received")
        return LoginResult("not-authenticated", messages, self.cookie_names())

    def fetch_config(self) -> VpnConfig | None:
        response = self.get("remote/fortisslvpn_xml?dual_stack=1")
        if response.status != 200 or "<sslvpn-tunnel" not in response.text:
            return None
        return parse_vpn_config(response.text)

    def get(self, path: str) -> HttpResponse:
        return self._request("GET", path)

    def post_form(self, path: str, data: dict[str, str]) -> HttpResponse:
        body = urlencode(data).encode("utf-8")
        return self._request(
            "POST",
            path,
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def cookie_names(self) -> list[str]:
        return sorted({cookie.name for cookie in self.cookies})

    def _svpncookie(self) -> str | None:
        for cookie in self.cookies:
            if cookie.name == "SVPNCOOKIE" and cookie.value:
                return cookie.value
        return None

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        url = urljoin(self.base_url, path)
        merged_headers = {
            "User-Agent": self.user_agent,
            "Accept-Encoding": "identity",
            **(headers or {}),
        }
        request = Request(url, data=body, headers=merged_headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as res:
                raw = res.read()
                return HttpResponse(
                    status=res.status,
                    url=res.url,
                    headers=dict(res.headers.items()),
                    text=raw.decode("utf-8", errors="replace"),
                )
        except HTTPError as exc:
            raw = exc.read()
            return HttpResponse(
                status=exc.code,
                url=exc.url,
                headers=dict(exc.headers.items()),
                text=raw.decode("utf-8", errors="replace"),
            )


def classify_login_response(text: str) -> str:
    lowered = (text or "").lower()
    if "tokeninfo=" in lowered:
        if "ftm_push" in lowered:
            return "tokeninfo-mfa-push-challenge"
        return "tokeninfo-mfa-challenge"
    if "<form" in lowered:
        return "html-login-or-mfa-form"
    if "svpn" in lowered or "sslvpn" in lowered:
        return "vpn-portal-or-config"
    if looks_like_login_page(text):
        return "login-page"
    if not text:
        return "empty"
    return "other"


def parse_tokeninfo(text: str) -> dict[str, str]:
    if "tokeninfo=" not in text:
        return {}
    fields: dict[str, str] = {}
    for part in text.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key.strip()] = value.strip()
    return fields


def build_tokeninfo_response(
    *,
    username: str,
    realm: str = "",
    token_fields: dict[str, str],
    mfa_code: str | None,
    blank_mfa: bool,
) -> dict[str, str]:
    data = {"username": username}
    if realm:
        data["realm"] = realm
    for key in ("reqid", "polid", "grp", "portal", "peer", "magic"):
        if key in token_fields and token_fields[key]:
            data[key] = token_fields[key]

    tokeninfo = token_fields.get("tokeninfo", "")
    if tokeninfo.startswith("ftm_push") and blank_mfa:
        data.pop("magic", None)
        data["code"] = ""
        data["ftmpush"] = "1"
    else:
        data["code"] = "" if blank_mfa else (mfa_code or "")
    return data


def parse_html_form(text: str) -> dict[str, str]:
    if "<form" not in text.lower():
        return {}
    parser = HiddenFormParser()
    parser.feed(text)
    fields = dict(parser.fields)
    if parser.password_name:
        fields["_password_name"] = parser.password_name
    return fields


def looks_like_login_page(text: str) -> bool:
    lowered = text.lower()
    return "remote/login" in lowered or "login" in lowered and "password" in lowered


def parse_vpn_config(xml_text: str) -> VpnConfig:
    root = ET.fromstring(xml_text.strip())
    config = VpnConfig(dtls_enabled=root.attrib.get("dtls") == "1")

    fos = root.find("fos")
    if fos is not None:
        pieces = [fos.attrib.get("platform", "")]
        version = ".".join(
            part for part in (fos.attrib.get("major"), fos.attrib.get("minor"), fos.attrib.get("patch")) if part
        )
        if version:
            pieces.append(version)
        if fos.attrib.get("build"):
            pieces.append("build " + fos.attrib["build"])
        config.platform = " ".join(part for part in pieces if part)

    idle_timeout = root.find("idle-timeout")
    if idle_timeout is not None and idle_timeout.attrib.get("val", "").isdigit():
        config.idle_timeout_minutes = int(idle_timeout.attrib["val"]) // 60

    auth_timeout = root.find("auth-timeout")
    if auth_timeout is not None and auth_timeout.attrib.get("val", "").isdigit():
        config.auth_timeout_seconds = int(auth_timeout.attrib["val"])

    auth_ses = root.find("auth-ses")
    if auth_ses is not None and "tun-connect-without-reauth" in auth_ses.attrib:
        config.reconnect_without_reauth = auth_ses.attrib["tun-connect-without-reauth"] == "1"

    for family in root:
        if family.tag not in {"ipv4", "ipv6"}:
            continue
        collect_family_config(family, config)
    return config


def collect_family_config(family: ET.Element, config: VpnConfig) -> None:
    for node in family:
        if node.tag == "assigned-addr":
            if node.attrib.get("ipv4"):
                config.assigned_ipv4.append(node.attrib["ipv4"])
            if node.attrib.get("ipv6"):
                suffix = "/" + node.attrib["prefix-len"] if node.attrib.get("prefix-len") else ""
                config.assigned_ipv6.append(node.attrib["ipv6"] + suffix)
        elif node.tag == "dns":
            for attr in ("ip", "ipv6"):
                if node.attrib.get(attr):
                    config.dns.append(node.attrib[attr])
            if node.attrib.get("domain"):
                config.search_domains.append(node.attrib["domain"])
        elif node.tag == "split-dns":
            domains = node.attrib.get("domains")
            if domains:
                config.search_domains.extend(part.strip() for part in domains.split(",") if part.strip())
            for key, value in node.attrib.items():
                if re.fullmatch(r"dnsserver\d+", key) and value:
                    config.dns.append(value)
        elif node.tag == "split-tunnel-info":
            negate = node.attrib.get("negate") == "1"
            target = config.exclude_routes if negate else config.routes
            target.extend(format_route(addr) for addr in node.findall("addr"))


def format_route(node: ET.Element) -> str:
    if node.attrib.get("ip"):
        return node.attrib["ip"] + "/" + node.attrib.get("mask", "")
    if node.attrib.get("ipv6"):
        return node.attrib["ipv6"] + "/" + node.attrib.get("prefix-len", "")
    return ""


def summarize_config(config: VpnConfig | None) -> Iterable[str]:
    if config is None:
        yield "config: not fetched"
        return
    yield f"platform: {config.platform or 'unknown'}"
    yield f"dtls: {'enabled' if config.dtls_enabled else 'disabled'}"
    if config.assigned_ipv4:
        yield "assigned IPv4: " + ", ".join(config.assigned_ipv4)
    if config.assigned_ipv6:
        yield "assigned IPv6: " + ", ".join(config.assigned_ipv6)
    if config.dns:
        yield "DNS: " + ", ".join(dict.fromkeys(config.dns))
    if config.search_domains:
        yield "search domains: " + ", ".join(dict.fromkeys(config.search_domains))
    if config.routes:
        yield f"routes: {len(config.routes)}"
    if config.exclude_routes:
        yield f"excluded routes: {len(config.exclude_routes)}"
    if config.idle_timeout_minutes is not None:
        yield f"idle timeout: {config.idle_timeout_minutes} minutes"
    if config.auth_timeout_seconds is not None:
        yield f"auth timeout: {config.auth_timeout_seconds} seconds"
    if config.reconnect_without_reauth is not None:
        yield f"reconnect without reauth: {config.reconnect_without_reauth}"
