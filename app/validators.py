import ipaddress
import re
from urllib.parse import urlparse

_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_STATUS = re.compile(r"^\d{3}(-\d{3})?(,\s*\d{3}(-\d{3})?)*$")


def text(v, label="Value", required=False, maxlen=500):
    v = (v or "").strip()
    if required and not v:
        raise ValueError(f"{label} is required")
    if len(v) > maxlen:
        raise ValueError(f"{label} is too long (max {maxlen})")
    return v or None


def ip(v, required=True):
    v = (v or "").strip()
    if not v:
        if required:
            raise ValueError("IP address is required")
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ValueError("Not a valid IPv4/IPv6 address")


def host(v):
    v = (v or "").strip()
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        if _HOST.match(v):
            return v
        raise ValueError("Not a valid IP address or hostname")


def port(v):
    v = (v or "").strip()
    if not v:
        return None
    if not v.isdigit() or not 1 <= int(v) <= 65535:
        raise ValueError("Port must be 1-65535")
    return int(v)


def url(v):
    v = (v or "").strip()
    if not v:
        return None
    p = urlparse(v)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError("Must be a full http:// or https:// URL")
    return v


def path(v):
    v = (v or "").strip()
    if v and not v.startswith("/"):
        v = "/" + v
    return v or None


def number(v, cast, lo, hi, label="Value"):
    v = (v or "").strip()
    if not v:
        return None
    try:
        n = cast(v)
    except ValueError:
        raise ValueError(f"{label} must be a number")
    if not lo <= n <= hi:
        raise ValueError(f"{label} must be between {lo} and {hi}")
    return n


def choice(v, options):
    if v not in options:
        raise ValueError("Invalid choice")
    return v


def expected_status(v):
    v = (v or "").strip()
    if v and not _STATUS.match(v):
        raise ValueError("Use e.g. 200, 200-299 or 200,301-302")
    return v or None


class Form:
    """Collects per-field validation errors."""

    def __init__(self, src):
        self.src, self.errors = src, {}

    def get(self, key, fn, *args):
        try:
            return fn(self.src.get(key, ""), *args)
        except ValueError as e:
            self.errors[key] = str(e)
            return None
