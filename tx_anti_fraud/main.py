"""Точка входу утиліти."""

from pathlib import Path
import tempfile

from .core import calc_stats, group_tx, iter_tx, read_log, write_safe
from .exceptions import FileIOError, TxError

__all__ = ["main"]


def make_report(stats, grouped, errors):
    out = [
        f"Транзакцій: {stats['count']} | Сума: {stats['total']:.2f}",
        f"Підозрілих: {stats['suspicious']} | Критичних: {stats['critical']}",
        f"Терміналів: {stats['terminals']} | Ризикові: {', '.join(stats['risky_terminals']) or '-'}",
        f"Помилок: {len(errors)}",
    ]
    for tid in sorted(grouped):
        s = sum((t.amount for t in grouped[tid]), 0.0)
        out.append(f"  {tid}: {len(grouped[tid])} шт., {s:.2f}")
    if errors:
        out.extend(f"  ! {e}" for e in errors)
    return "\n".join(out) + "\n"


def main():
    base = Path(tempfile.gettempdir()) / "tx_mini"
    log_file = base / "tx.log"
    out_file = base / "report.txt"

    base.mkdir(parents=True, exist_ok=True)
    with open(log_file, "w", encoding="utf-8") as fh:
        fh.write(
            "TERM-01 | 0x0003 | 100.00 | 2026-11-22T12:00:00Z\n"
            "TERM-02 | 0x0041 | 11000.00 | 2026-11-22T12:05:00Z\n"
            "TERM-01 | 0x0080 | 500.00 | 2026-11-22T12:10:00Z\n"
            "BROKEN\n"
            "TERM-03 | 0xFFFFF | 100.00 | 2026-11-22T12:15:00Z\n"
        )

    extra_line = None
    raw_amt = input("Введіть суму додаткової транзакції: ").strip()
    if raw_amt:
        extra_line = f"TERM-01 | 0x0001 | {raw_amt} | 2026-11-23T12:00:00Z"

    errors = []
    txs = []
    status = "INIT"

    try:
        lines = list(read_log(log_file))
        if extra_line:
            lines.append(extra_line)
        txs = list(iter_tx(lines, errors=errors))
    except TxError as exc:
        errors.append(str(exc))
        status = "READ_ERR"
    
    report = make_report(calc_stats(txs), group_tx(txs, sort_items=True), errors)

    try:
        write_safe(out_file, report)
    except FileIOError as exc:
        print(f"Помилка: {exc}")
        return 1
    else:
        if status == "INIT":
            status = "OK"
    finally:
        pass

    print(f"Статус={status}, звіт={out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())