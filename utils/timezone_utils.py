import os
import time


BEIJING_TIMEZONE = "Asia/Shanghai"


def apply_beijing_timezone() -> str:
    """Force process timezone to Beijing time."""
    os.environ["TZ"] = BEIJING_TIMEZONE
    tzset = getattr(time, "tzset", None)
    if callable(tzset):
        try:
            tzset()
        except Exception:
            pass
    return os.environ.get("TZ", BEIJING_TIMEZONE)
