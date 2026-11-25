"""Key/value settings stored in SQLite, with defaults so the app works out of the box."""
from .models import db, Setting

DEFAULTS = {
    "monitoring_enabled": "1",
    "check_times": "00:00",
    "check_days": "0,1,2,3,4,5,6",  # 0 = Monday
    "timezone": "",                  # empty = server timezone
    "tcp_timeout": "3",
    "http_timeout": "5",
    "http_enabled": "1",
    "retries": "2",
    "retry_delay": "30",
    "history_days": "90",
    "cred_lock_minutes": "5",        # 0 = never auto-lock
    "pin_hash": "",
    "last_run_at": "",
    "last_run_id": "",
    "last_run_trigger": "",
}


def get(key):
    row = Setting.query.filter_by(setting_key=key).first()
    return row.setting_value if row else DEFAULTS.get(key, "")


def get_bool(key):
    return get(key) in ("1", "true", "True")


def get_int(key):
    try:
        return int(float(get(key)))
    except ValueError:
        return int(float(DEFAULTS[key]))


def get_float(key):
    try:
        return float(get(key))
    except ValueError:
        return float(DEFAULTS[key])


def set_many(values, commit=True):
    for key, value in values.items():
        if isinstance(value, bool):
            value = "1" if value else "0"
        row = Setting.query.filter_by(setting_key=key).first()
        if row:
            row.setting_value = str(value)
        else:
            db.session.add(Setting(setting_key=key, setting_value=str(value)))
    if commit:
        db.session.commit()
