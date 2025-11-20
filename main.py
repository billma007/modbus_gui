import struct
import time
from dataclasses import dataclass
from typing import Tuple

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

try:
    import serial
    from serial.tools import list_ports # type: ignore
except Exception:
    serial = None
    list_ports = None

from crc16 import *
from register_float import pack_float_to_registers, unpack_float_from_registers



@dataclass
class SerialConfig:
    port: str
    baudrate: int = 9600
    parity: str = "N"
    stopbits: int = 1


class RTUTransport:
    def __init__(self, cfg: SerialConfig, demo: bool = False):
        self.cfg = cfg
        self.demo = demo
        self.ser = None

    def open(self):
        if self.demo or serial is None:
            return
        self.ser = serial.Serial(
            self.cfg.port,
            self.cfg.baudrate,
            bytesize=8,
            parity=self.cfg.parity,
            stopbits=self.cfg.stopbits,
            timeout=0.5,
            write_timeout=0.5
        )

    def close(self):
        if self.ser:
            self.ser.close()
            self.ser = None

    def transact(self, pdu: bytes) -> bytes:
        """
        发送 PDU（不含 CRC），返回完整响应帧（含 CRC）。
        PDU: [slave][fc][addr_hi][addr_lo][data...]
        """
        frame = append_crc(pdu)

        # 演示模式：不走实际串口，返回模拟数据
        if self.demo or serial is None or self.ser is None:
            slave = pdu[0]
            fc = pdu[1]
            if fc == 3:  # 读保持寄存器
                # 模拟返回 3 个寄存器：0x0072, 0x0202, 0x00BF
                payload = bytes([slave, fc, 6, 0x00, 0x72, 0x02, 0x02, 0x00, 0xBF])
                return append_crc(payload)
            elif fc == 6:  # 写单寄存器，直接回显
                return append_crc(pdu)
            else:
                # 异常响应示例
                err_payload = bytes([slave, fc | 0x80, 0x01])
                return append_crc(err_payload)

        # 真正串口通信
        self.ser.reset_input_buffer()
        self.ser.write(frame)
        self.ser.flush()

        # 读回应头 3 字节：slave, fc, byte_count / 其他
        hdr = self.ser.read(3)
        if len(hdr) < 3:
            return b""

        slave, fc, bc = hdr
        if fc in (3, 4):
            rest = self.ser.read(bc + 2)  # data + CRC
        else:
            rest = self.ser.read(5)       # 一般固定长度 + CRC
        return hdr + rest


class ModbusApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Modbus RTU 实验系统 - Tkinter 版")
        self.root.geometry("980x700")

        # 串口配置变量
        self.demo_var = tk.BooleanVar(value=False)
        self.port_var = tk.StringVar()
        self.baud_var = tk.IntVar(value=9600)
        self.parity_var = tk.StringVar(value="N")
        self.stopbits_var = tk.IntVar(value=1)
        self.slave_var = tk.IntVar(value=3)

        # CRC 工具变量
        self.crc_input_var = tk.StringVar(value="03 03 00 00 00 03")

        # 读寄存器变量
        self.read_start_var = tk.IntVar(value=0)
        self.read_qty_var = tk.IntVar(value=3)
        self.read_order_var = tk.StringVar(value="ABCD")

        # 写单寄存器变量
        self.write_addr_var = tk.IntVar(value=3)
        self.write_value_var = tk.StringVar(value="254")

        # 写浮点数变量
        self.float_addr_var = tk.IntVar(value=10)
        self.float_value_var = tk.DoubleVar(value=12.34)
        self.float_order_var = tk.StringVar(value="ABCD")

        self._build_ui()

    # ---------- UI 构建 ----------
    def _build_ui(self):
        # 顶部：串口设置
        frm_serial = ttk.LabelFrame(self.root, text="串口设置", padding=8)
        frm_serial.pack(fill=tk.X, padx=10, pady=5)

        ttk.Checkbutton(frm_serial, text="演示模式（无真实串口）",
                        variable=self.demo_var).grid(row=0, column=0, sticky="w", padx=5, pady=2)

        ttk.Label(frm_serial, text="端口：").grid(row=0, column=1, sticky="e")
        self.cmb_port = ttk.Combobox(frm_serial, width=12, textvariable=self.port_var)
        ports = [p.device for p in list_ports.comports()] if list_ports else []
        self.cmb_port["values"] = ports
        if ports:
            self.cmb_port.current(0)
        self.cmb_port.grid(row=0, column=2, padx=5)

        ttk.Label(frm_serial, text="波特率：").grid(row=0, column=3, sticky="e")
        cmb_baud = ttk.Combobox(frm_serial, width=8, textvariable=self.baud_var,
                                values=[9600, 19200, 38400, 57600, 115200])
        cmb_baud.grid(row=0, column=4, padx=5)

        ttk.Label(frm_serial, text="校验位：").grid(row=0, column=5, sticky="e")
        cmb_parity = ttk.Combobox(frm_serial, width=5, textvariable=self.parity_var,
                                  values=["N", "E", "O"])
        cmb_parity.grid(row=0, column=6, padx=5)

        ttk.Label(frm_serial, text="停止位：").grid(row=0, column=7, sticky="e")
        cmb_stop = ttk.Combobox(frm_serial, width=5, textvariable=self.stopbits_var,
                                values=[1, 2])
        cmb_stop.grid(row=0, column=8, padx=5)

        ttk.Label(frm_serial, text="从站地址：").grid(row=0, column=9, sticky="e")
        ttk.Spinbox(frm_serial, from_=1, to=247, width=5,
                    textvariable=self.slave_var).grid(row=0, column=10, padx=5)

        # 中部：左右分栏
        frm_main = ttk.Frame(self.root)
        frm_main.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 左侧：CRC + 读写寄存器
        frm_left = ttk.Frame(frm_main)
        frm_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._build_crc_frame(frm_left)
        self._build_read_frame(frm_left)
        self._build_write_frame(frm_left)
        self._build_float_frame(frm_left)

        # 右侧：输出窗口
        frm_right = ttk.LabelFrame(frm_main, text="输出 / 日志", padding=5)
        frm_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.txt_output = scrolledtext.ScrolledText(frm_right, wrap=tk.WORD)
        self.txt_output.pack(fill=tk.BOTH, expand=True)

    def _build_crc_frame(self, parent):
        frm_crc = ttk.LabelFrame(parent, text="CRC16 计算工具", padding=5)
        frm_crc.pack(fill=tk.X, pady=5)

        ttk.Label(frm_crc, text="十六进制帧（不含 CRC）：").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm_crc, textvariable=self.crc_input_var, width=45).grid(row=1, column=0, padx=5, pady=2)

        ttk.Button(frm_crc, text="计算 CRC16", command=self.on_calc_crc)\
            .grid(row=1, column=1, padx=5, pady=2, sticky="w")

    def _build_read_frame(self, parent):
        frm = ttk.LabelFrame(parent, text="功能码 03：读取保持寄存器", padding=5)
        frm.pack(fill=tk.X, pady=5)

        ttk.Label(frm, text="起始地址：").grid(row=0, column=0, sticky="e")
        ttk.Entry(frm, width=8, textvariable=self.read_start_var).grid(row=0, column=1, padx=5)

        ttk.Label(frm, text="数量：").grid(row=0, column=2, sticky="e")
        ttk.Entry(frm, width=8, textvariable=self.read_qty_var).grid(row=0, column=3, padx=5)

        ttk.Label(frm, text="浮点字节序：").grid(row=0, column=4, sticky="e")
        ttk.Combobox(frm, width=8, textvariable=self.read_order_var,
                     values=["ABCD", "BADC", "CDAB", "DCBA"]).grid(row=0, column=5, padx=5)

        ttk.Button(frm, text="发送读取命令", command=self.on_read_registers)\
            .grid(row=0, column=6, padx=5)

    def _build_write_frame(self, parent):
        frm = ttk.LabelFrame(parent, text="功能码 06：写单个保持寄存器", padding=5)
        frm.pack(fill=tk.X, pady=5)

        ttk.Label(frm, text="寄存器地址：").grid(row=0, column=0, sticky="e")
        ttk.Entry(frm, width=8, textvariable=self.write_addr_var).grid(row=0, column=1, padx=5)

        ttk.Label(frm, text="写入值（十进制或 0x..）：").grid(row=0, column=2, sticky="e")
        ttk.Entry(frm, width=12, textvariable=self.write_value_var).grid(row=0, column=3, padx=5)

        ttk.Button(frm, text="发送写入命令", command=self.on_write_single)\
            .grid(row=0, column=4, padx=5)

    def _build_float_frame(self, parent):
        frm = ttk.LabelFrame(parent, text="写浮点数（占用连续两个寄存器）", padding=5)
        frm.pack(fill=tk.X, pady=5)

        ttk.Label(frm, text="起始地址：").grid(row=0, column=0, sticky="e")
        ttk.Entry(frm, width=8, textvariable=self.float_addr_var).grid(row=0, column=1, padx=5)

        ttk.Label(frm, text="浮点值：").grid(row=0, column=2, sticky="e")
        ttk.Entry(frm, width=10, textvariable=self.float_value_var).grid(row=0, column=3, padx=5)

        ttk.Label(frm, text="字节序：").grid(row=0, column=4, sticky="e")
        ttk.Combobox(frm, width=8, textvariable=self.float_order_var,
                     values=["ABCD", "BADC", "CDAB", "DCBA"]).grid(row=0, column=5, padx=5)

        ttk.Button(frm, text="写入浮点数", command=self.on_write_float)\
            .grid(row=0, column=6, padx=5)

    # ---------- 事件处理 ----------

    def log(self, text: str):
        self.txt_output.insert(tk.END, text + "\n")
        self.txt_output.see(tk.END)

    def get_serial_config(self) -> SerialConfig:
        return SerialConfig(
            port=self.port_var.get(),
            baudrate=self.baud_var.get(),
            parity=self.parity_var.get(),
            stopbits=self.stopbits_var.get()
        )

    def on_calc_crc(self):
        try:
            data = bytes(int(x, 16) for x in self.crc_input_var.get().strip().split())
        except Exception:
            messagebox.showerror("错误", "输入格式有误，请输入十六进制字节，例如：03 03 00 00 00 03")
            return

        crc_val = crc16_modbus(data)
        frame_full = append_crc(data)
        msg = (f"输入帧: {bytes_to_hex(data)}\n"
               f"CRC16 = 0x{crc_val:04X} （低字节在前：{crc_val & 0xFF:02X} {(crc_val >> 8) & 0xFF:02X}）\n"
               f"完整帧: {bytes_to_hex(frame_full)}")
        self.log(msg)

    def on_read_registers(self):
        cfg = self.get_serial_config()
        transport = RTUTransport(cfg, demo=self.demo_var.get())
        pdu = bytes([
            self.slave_var.get(),
            3,  # 功能码 03
            (self.read_start_var.get() >> 8) & 0xFF,
            self.read_start_var.get() & 0xFF,
            (self.read_qty_var.get() >> 8) & 0xFF,
            self.read_qty_var.get() & 0xFF
        ])

        try:
            t0 = time.time()
            transport.open()
            resp = transport.transact(pdu)
            t1 = time.time()
        except Exception as e:
            messagebox.showerror("错误", f"串口通信失败：{e}")
            transport.close()
            return
        finally:
            transport.close()

        if not resp:
            self.log("未收到从机响应。")
            return

        self.log(f"[读寄存器] 响应时间：{(t1 - t0)*1000:.1f} ms")
        self.log(f"原始响应帧: {bytes_to_hex(resp)}")
        self.log(f"CRC 校验: {'通过' if verify_crc(resp) else '失败'}")

        if len(resp) >= 5 and resp[1] == 3:
            bc = resp[2]
            data = resp[3:3 + bc]
            regs = [(data[i] << 8) | data[i+1] for i in range(0, len(data), 2)]
            self.log("寄存器内容：")
            for idx, val in enumerate(regs):
                addr = self.read_start_var.get() + idx
                self.log(f"  地址 {addr}: 十进制 {val}, 十六进制 0x{val:04X}")

            if len(regs) >= 2:
                order = self.read_order_var.get()
                fval = unpack_float_from_registers(regs[0], regs[1], order)
                self.log(f"按字节序 {order} 解析的浮点值: {fval}")
        elif len(resp) >= 3 and (resp[1] & 0x80):
            self.log(f"从机异常响应：功能码 {resp[1]:02X}，异常码 {resp[2]:02X}")

    def on_write_single(self):
        # 解析写入值，可以是十进制或 0x.. 十六进制
        try:
            val = int(self.write_value_var.get(), 0)
        except Exception:
            messagebox.showerror("错误", "写入值格式错误，可输入 10 或 0x0A 形式。")
            return

        cfg = self.get_serial_config()
        transport = RTUTransport(cfg, demo=self.demo_var.get())
        addr = self.write_addr_var.get()
        pdu = bytes([
            self.slave_var.get(),
            6,  # 功能码 06
            (addr >> 8) & 0xFF,
            addr & 0xFF,
            (val >> 8) & 0xFF,
            val & 0xFF
        ])

        try:
            t0 = time.time()
            transport.open()
            resp = transport.transact(pdu)
            t1 = time.time()
        except Exception as e:
            messagebox.showerror("错误", f"串口通信失败：{e}")
            transport.close()
            return
        finally:
            transport.close()

        if not resp:
            self.log("未收到从机响应。")
            return

        self.log(f"[写单寄存器] 响应时间：{(t1 - t0)*1000:.1f} ms")
        self.log(f"原始响应帧: {bytes_to_hex(resp)}")
        self.log(f"CRC 校验: {'通过' if verify_crc(resp) else '失败'}")

    def on_write_float(self):
        addr = self.float_addr_var.get()
        value = self.float_value_var.get()
        order = self.float_order_var.get()

        try:
            reg_hi, reg_lo = pack_float_to_registers(value, order)
        except Exception as e:
            messagebox.showerror("错误", f"浮点数拆分失败：{e}")
            return

        cfg = self.get_serial_config()
        transport = RTUTransport(cfg, demo=self.demo_var.get())

        pdu1 = bytes([
            self.slave_var.get(), 6,
            (addr >> 8) & 0xFF,
            addr & 0xFF,
            (reg_hi >> 8) & 0xFF,
            reg_hi & 0xFF
        ])
        pdu2 = bytes([
            self.slave_var.get(), 6,
            ((addr + 1) >> 8) & 0xFF,
            (addr + 1) & 0xFF,
            (reg_lo >> 8) & 0xFF,
            reg_lo & 0xFF
        ])

        try:
            transport.open()
            r1 = transport.transact(pdu1)
            time.sleep(0.05)
            r2 = transport.transact(pdu2)
        except Exception as e:
            messagebox.showerror("错误", f"串口通信失败：{e}")
            transport.close()
            return
        finally:
            transport.close()

        self.log(f"[写浮点数] 值 {value} 已拆分写入寄存器 {addr} 和 {addr+1}（字节序 {order}）")
        self.log(f"  响应1: {bytes_to_hex(r1)} （CRC {'通过' if verify_crc(r1) else '失败'}）")
        self.log(f"  响应2: {bytes_to_hex(r2)} （CRC {'通过' if verify_crc(r2) else '失败'}）")


if __name__ == "__main__":
    root = tk.Tk()
    app = ModbusApp(root)
    root.mainloop()
