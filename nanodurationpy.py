# -*- coding: UTF-8 -*-

# originally from https://github.com/icholy/durationpy/blob/master/durationpy/duration.py

import re
import datetime
import pandas

_nanosecond_size  = 1
_microsecond_size = 1000 * _nanosecond_size
_millisecond_size = 1000 * _microsecond_size
_second_size      = 1000 * _millisecond_size
_minute_size      = 60   * _second_size
_hour_size        = 60   * _minute_size
_day_size         = 24   * _hour_size
_week_size        = 7    * _day_size
_month_size       = 30   * _day_size
_year_size        = 365  * _day_size

units = {
    "ns": _nanosecond_size,
    "us": _microsecond_size,
    "µs": _microsecond_size,
    "μs": _microsecond_size,
    "ms": _millisecond_size,
    "s":  _second_size,
    "m":  _minute_size,
    "h":  _hour_size,
    "d":  _day_size,
    "w":  _week_size,
    "mm": _month_size,
    "y":  _year_size,
}


def from_str(duration):
    """Parse a duration string to a datetime.timedelta"""

    if duration in ("0", "+0", "-0"):
        return datetime.timedelta()

    pattern = re.compile('([\d\.]+)([a-zµμ]+)')
    total = 0
    sign = -1 if duration[0] == '-' else 1
    matches = pattern.findall(duration)

    if not len(matches):
        raise Exception("Invalid duration {}".format(duration))

    for (value, unit) in matches:
        if unit not in units:
            raise Exception(
                "Unknown unit {} in duration {}".format(unit, duration))
        try:
            total += float(value) * units[unit]
        except:
            raise Exception(
                "Invalid value {} in duration {}".format(value, duration))

    #microseconds = total / _microsecond_size
    nanoseconds = int(total)
    return pandas.Timedelta(nanoseconds=sign * nanoseconds)
