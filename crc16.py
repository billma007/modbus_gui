def crc16_modbus(data: bytes) -> int:
    """标准 Modbus CRC16 算法"""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def append_crc(frame: bytes) -> bytes:
    """在帧末尾追加 CRC，低字节在前（小端）"""
    code = crc16_modbus(frame)
    return frame + bytes([code & 0xFF, (code >> 8) & 0xFF])


def verify_crc(frame: bytes) -> bool:
    """校验接收帧的 CRC 是否正确"""
    if len(frame) < 3:
        return False
    recv_crc = frame[-2] | (frame[-1] << 8)
    return crc16_modbus(frame[:-2]) == recv_crc


def bytes_to_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)