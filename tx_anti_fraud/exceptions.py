"""Винятки для обробки журналу транзакцій."""

__all__ = ["TxError", "FormatError", "MaskError", "FileIOError"]


class TxError(Exception):
    """Базовий виняток."""


class FormatError(TxError):
    """Помилка формату запису або поля."""


class MaskError(TxError):
    """Некоректна бітова маска."""


class FileIOError(TxError):
    """Помилка читання чи запису файлу."""