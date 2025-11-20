import struct
from typing import Tuple



def pack_float_to_registers(value: float, byte_order: str = "ABCD") -> Tuple[int, int]:
    """浮点数 -> 两个 16 位寄存器"""
    raw = struct.pack(">f", value)  # 大端 float
    A, B, C, D = raw

    mapping = {
        "ABCD": bytes([A, B, C, D]),
        "BADC": bytes([B, A, D, C]),
        "CDAB": bytes([C, D, A, B]),
        "DCBA": bytes([D, C, B, A]),
    }
    ordered = mapping[byte_order]
    reg_hi = (ordered[0] << 8) | ordered[1]
    reg_lo = (ordered[2] << 8) | ordered[3]
    return reg_hi, reg_lo


def unpack_float_from_registers(reg_hi: int, reg_lo: int, byte_order: str = "ABCD") -> float:
    """两个 16 位寄存器 -> 浮点数"""
    A, B = (reg_hi >> 8) & 0xFF, reg_hi & 0xFF
    C, D = (reg_lo >> 8) & 0xFF, reg_lo & 0xFF
    mapping = {
        "ABCD": bytes([A, B, C, D]),
        "BADC": bytes([B, A, D, C]),
        "CDAB": bytes([C, D, A, B]),
        "DCBA": bytes([D, C, B, A]),
    }
    ordered = mapping[byte_order]
    return struct.unpack(">f", ordered)[0]