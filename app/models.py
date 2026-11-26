from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    """All timestamps are stored as naive UTC and converted for display."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def build_url(protocol, host, port, path):
    if not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    default = 443 if protocol == "https" else 80
    shown = f":{port}" if port and port != default else ""
    return f"{protocol}://{host}{shown}{path or ''}"


class Stamped:
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class Monitored:
    """Per-target monitoring overrides. NULL = use the global default."""
    mon_enabled = db.Column(db.Boolean, default=True, nullable=False)
    timeout = db.Column(db.Float)
    retries = db.Column(db.Integer)
    retry_delay = db.Column(db.Integer)


class Device(Stamped, Monitored, db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(253))
    description = db.Column(db.String(500))
    device_type = db.Column(db.String(60))
    notes = db.Column(db.Text)
    check_method = db.Column(db.String(10), default="ping", nullable=False)  # ping | tcp
    check_port = db.Column(db.Integer)
    web_protocol = db.Column(db.String(5))      # http | https | NULL (device has no web interface)
    web_port = db.Column(db.Integer)
    web_path = db.Column(db.String(300))
    web_url = db.Column(db.String(500))         # custom URL, overrides the generated one

    @property
    def open_url(self):
        if self.web_url:
            return self.web_url
        if self.web_port or self.web_protocol:
            return build_url(self.web_protocol or "http", self.ip_address, self.web_port, self.web_path)
        return None

    services = db.relationship("Service", backref="device", cascade="all, delete-orphan",
                               foreign_keys="Service.device_id", order_by="Service.name")


class Service(Stamped, Monitored, db.Model):
    __tablename__ = "services"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500))
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"))
    ip_address = db.Column(db.String(45))      # blank = use the device's IP
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(5), default="http", nullable=False)
    access_path = db.Column(db.String(300))
    quick_access_url = db.Column(db.String(500))
    management_type = db.Column(db.String(10), default="direct", nullable=False)  # direct | external | manual
    management_service_id = db.Column(db.Integer, db.ForeignKey("services.id", ondelete="SET NULL"))
    management_url = db.Column(db.String(500))
    ssh_host = db.Column(db.String(253))
    ssh_port = db.Column(db.Integer)
    ssh_username = db.Column(db.String(120))
    management_notes = db.Column(db.Text)
    notes = db.Column(db.Text)
    check_method = db.Column(db.String(10), default="tcp", nullable=False)  # tcp | tcp_http
    http_expected = db.Column(db.String(60))   # e.g. "200-299"; blank = 200-299
    management_service = db.relationship("Service", remote_side=[id], foreign_keys=[management_service_id])

    @property
    def host(self):
        return self.ip_address or (self.device.ip_address if self.device else "")

    @property
    def eff_port(self):
        return self.port or (443 if self.protocol == "https" else 80)

    @property
    def base_url(self):
        return build_url(self.protocol, self.host, self.port, self.access_path)

    @property
    def open_url(self):
        return self.quick_access_url or self.base_url

    @property
    def manage_url(self):
        if self.management_type == "direct":
            return self.open_url
        if self.management_type == "external":
            if self.management_url:
                return self.management_url
            return self.management_service.open_url if self.management_service else None
        return None

    @property
    def ssh_command(self):
        if self.management_type != "manual" or not self.ssh_host:
            return None
        user = f"{self.ssh_username}@" if self.ssh_username else ""
        port = f" -p {self.ssh_port}" if self.ssh_port and self.ssh_port != 22 else ""
        return f"ssh {user}{self.ssh_host}{port}"


CRED_KINDS = [("login", "Login"), ("ssh", "SSH"), ("web", "Web login"), ("api_key", "API key"), ("other", "Other")]


class Credential(Stamped, db.Model):
    __tablename__ = "credentials"
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey("services.id", ondelete="SET NULL"))
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="SET NULL"))
    kind = db.Column(db.String(12), default="login", nullable=False)   # login | ssh | web | api_key | other
    port = db.Column(db.Integer)                                       # e.g. 22 for SSH, 8080 for a web login
    encrypted_api_key = db.Column(db.Text, default="")
    username = db.Column(db.String(200))
    encrypted_password = db.Column(db.Text, default="")
    login_url = db.Column(db.String(500))
    description = db.Column(db.String(500))
    notes = db.Column(db.Text)
    service = db.relationship("Service", backref=db.backref("credentials", order_by="Credential.id"))
    device = db.relationship("Device", backref=db.backref("credentials", order_by="Credential.id"))


class MonitorHistory(db.Model):
    __tablename__ = "monitoring_history"
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.String(16), index=True)
    target_type = db.Column(db.String(10), nullable=False)   # device | service
    target_id = db.Column(db.Integer, nullable=False)
    check_type = db.Column(db.String(5), nullable=False)     # ping | tcp | http
    checked_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    status = db.Column(db.String(8), nullable=False)         # online | offline
    response_time = db.Column(db.Float)                      # ms
    http_status_code = db.Column(db.Integer)
    error_message = db.Column(db.String(300))
    attempt_number = db.Column(db.Integer, default=1)
    is_final = db.Column(db.Boolean, default=True, nullable=False)  # last attempt of that check
    target_host = db.Column(db.String(253))
    target_port = db.Column(db.Integer)
    __table_args__ = (db.Index("ix_hist_target", "target_type", "target_id", "checked_at"),)


class Setting(db.Model):
    __tablename__ = "settings"
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(60), unique=True, nullable=False)
    setting_value = db.Column(db.Text, default="")


class Group(db.Model):
    """A named set of permissions. Users belong to exactly one group."""
    __tablename__ = "groups"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=True, nullable=False)
    description = db.Column(db.String(300))
    permissions = db.Column(db.Text, default="", nullable=False)   # comma separated permission keys
    is_system = db.Column(db.Boolean, default=False, nullable=False)  # Administrator: locked

    @property
    def perm_set(self):
        return {p for p in (self.permissions or "").split(",") if p}


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("groups.id", ondelete="RESTRICT"), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    group = db.relationship("Group", backref="users")

    @property
    def perms(self):
        return self.group.perm_set if self.group else set()
