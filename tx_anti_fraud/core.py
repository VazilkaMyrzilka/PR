"""Парсинг, генератори, аналітика та робота з файлами."""

from datetime import datetime
import os
from pathlib import Path
import re
import tempfile

from .exceptions import FileIOError, FormatError, MaskError
from .models import NormalTx, RiskTx, Transaction

__all__ = [
    "TX_RE",
    "parse_tx",
    "read_log",
    "iter_tx",
    "filter_tx",
    "group_tx",
    "calc_stats",
    "write_safe",
]

TX_RE = re.compile(
    r"""
    ^\s*
    (?P<term>[A-Z0-9_-]{3,20})
    \s*\|\s*
    (?P<flags>(?:0[xX])?[0-9A-Fa-f]{1,4})
    \s*\|\s*
    (?P<amt>\d+(?:\.\d{1,2})?)
    \s*\|\s*
    (?P<ts>\S+)
    \s*$
    """,
    re.VERBOSE,
)


def parse_tx(line, line_no=0):
    m = TX_RE.match(line)
    if not m:
        raise FormatError(f"Рядок {line_no}: невірний формат.")
    try:
        flags = int(m.group("flags"), 16)
    except ValueError as exc:
        raise MaskError(f"Рядок {line_no}: невірна маска.") from exc
    try:
        amt = float(m.group("amt"))
        clean_ts = m.group("ts").rstrip("Z")
        ts = datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise FormatError(f"Рядок {line_no}: невірна сума або дата.") from exc

    probe = Transaction(m.group("term"), flags, amt, ts)
    cls = RiskTx if (probe.is_suspicious() or amt >= 10000.0) else NormalTx
    return cls(m.group("term"), flags, amt, ts)

def read_log(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield line.rstrip("\r\n")
    except OSError as exc:
        raise FileIOError(f"Читання '{path}': {exc}") from exc


def iter_tx(lines, *, errors=None):
    for idx, line in enumerate(lines, start=1):
        try:
            yield parse_tx(line, idx)
        except (FormatError, MaskError) as exc:
            if errors is not None:
                errors.append(str(exc))


def filter_tx(txs, *preds, min_amt=0.0, suspicious_only=False, **opts):
    terms = opts.get("terminals")
    for tx in txs:
        if tx.amount < min_amt:
            continue
        if suspicious_only and not tx.is_suspicious():
            continue
        if terms is not None and tx.terminal_id not in terms:
            continue
        if any(not p(tx) for p in preds):
            continue
        yield tx


def group_tx(
    txs,
    *args,
    sort_items=False,
    **kwargs,
):
    _ = args, kwargs
    grouped = {}
    for tx in txs:
        grouped.setdefault(tx.terminal_id, []).append(tx)
    if sort_items:
        for items in grouped.values():
            items.sort()
    return grouped

def calc_stats(txs, *args, critical_only=False, **kwargs):
    _ = args, kwargs
    rows = [t for t in txs if not critical_only or t.is_critical()]
    return {
        "count": sum(1 for _ in rows),
        "total": sum((t.amount for t in rows), 0.0),
        "suspicious": sum(1 for t in rows if t.is_suspicious()),
        "critical": sum(1 for t in rows if t.is_critical()),
        "terminals": len({t.terminal_id for t in rows}),
        "risky_terminals": sorted({t.terminal_id for t in rows if t.is_suspicious()}),
    }


def write_safe(path, content):
    tmp_name = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
            tmp_name = tmp.name
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, path)
    except OSError as exc:
        if tmp_name and os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass
        raise FileIOError(f"Запис '{path}': {exc}") from exc