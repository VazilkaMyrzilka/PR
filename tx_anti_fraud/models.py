"""Міксин аудиту та класи транзакцій."""

from datetime import datetime

from .exceptions import FormatError, MaskError

__all__ = [
    "FLAG_CHIP",
    "FLAG_PIN",
    "FLAG_FALLBACK",
    "FLAG_VELOCITY",
    "FLAG_TAMPER",
    "FLAG_BLACKLIST",
    "CRITICAL_FLAGS",
    "SUSPICIOUS_FLAGS",
    "AuditMixin",
    "Transaction",
    "NormalTx",
    "RiskTx",
]

FLAG_CHIP = 0x0001
FLAG_PIN = 0x0002
FLAG_FALLBACK = 0x0008
FLAG_VELOCITY = 0x0010
FLAG_TAMPER = 0x0040
FLAG_BLACKLIST = 0x0080

CRITICAL_FLAGS = FLAG_TAMPER | FLAG_BLACKLIST
SUSPICIOUS_FLAGS = CRITICAL_FLAGS | FLAG_VELOCITY | FLAG_FALLBACK


class AuditMixin:
    """Міксин запису подій аудиту."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = []

    @property
    def events(self):
        return tuple(self._events)

    def add_event(self, text):
        if not hasattr(self, "_events"):
            self._events = []
        self._events.append(text)


class Transaction:
    """Базовий клас транзакції."""

    def __init__(self, terminal_id, flags, amount, ts):
        self.terminal_id = terminal_id
        self.flags = flags
        self.amount = amount
        self.ts = ts

    @property
    def terminal_id(self):
        return self._terminal_id

    @terminal_id.setter
    def terminal_id(self, value):
        val = value.strip().upper()
        if not val:
            raise FormatError("Порожній ID термінала.")
        self._terminal_id = val

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, value):
        if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 0xFFFF):
            raise MaskError(f"Некоректна маска: {value!r}")
        self._flags = value

    @property
    def amount(self):
        return self._amount

    @amount.setter
    def amount(self, value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise FormatError("Некоректний тип суми.")
        val = float(value)
        if val < 0.0:
            raise FormatError("Від'ємна сума.")
        self._amount = val

    @property
    def ts(self):
        return self._ts

    @ts.setter
    def ts(self, value):
        self._ts = value

    def has_flag(self, mask):
        return (self._flags & mask) == mask

    def is_critical(self):
        return (self._flags & CRITICAL_FLAGS) != 0

    def is_suspicious(self):
        return (self._flags & SUSPICIOUS_FLAGS) != 0

    def __str__(self):
        tag = "CRIT" if self.is_critical() else ("RISK" if self.is_suspicious() else "OK")
        return f"[{tag}] {self.terminal_id} 0x{self.flags:04X} {self.amount:.2f} {self.ts.isoformat()}"

    def __repr__(self):
        return (
            f"{type(self).__name__}(terminal_id={self.terminal_id!r}, flags=0x{self.flags:04X}, "
            f"amount={self.amount!r}, ts={self.ts.isoformat()!r})"
        )

    def __eq__(self, other):
        if not isinstance(other, Transaction):
            return NotImplemented
        return (self.terminal_id, self.flags, self.amount, self.ts) == (
            other.terminal_id,
            other.flags,
            other.amount,
            other.ts,
        )

    def __lt__(self, other):
        if not isinstance(other, Transaction):
            return NotImplemented
        return (self.ts, self.amount, self.terminal_id) < (
            other.ts,
            other.amount,
            other.terminal_id,
        )


class NormalTx(Transaction):
    """Звичайна транзакція."""


class RiskTx(AuditMixin, Transaction):
    """Ризикова або велика транзакція з аудитом."""

    def __init__(self, terminal_id, flags, amount, ts, *, limit=10000.0):
        super().__init__(terminal_id, flags, amount, ts)
        self.add_event(f"Init 0x{self.flags:04X}, amount={self.amount:.2f}")
        if self.is_critical():
            self.add_event("Critical flag set.")
        if self.amount >= limit:
            self.add_event(f"Amount >= {limit:.2f}.")