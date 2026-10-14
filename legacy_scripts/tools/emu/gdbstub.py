"""Tiny client for DuckStation's GDB remote stub (127.0.0.1:2345).

Connecting halts the emulator. Call detach() (or close the socket after
`cont`) to let it run again. Unavailable registers come back as 'xxxxxxxx'
and are read as 0.

    from gdbstub import Gdb
    g = Gdb()
    print(hex(g.regs()["pc"]))
    ram = g.mem(0x80000000, 0x200000)
    g.detach()
"""

from __future__ import annotations

import socket
import struct
import time

REG_NAMES = ("zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 "
             "t8 t9 k0 k1 gp sp fp ra sr lo hi bad cause pc").split()


class Gdb:
    def __init__(self, port: int = 2345, retries: int = 60):
        for _ in range(retries):
            try:
                self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                break
            except OSError:
                time.sleep(0.5)
        else:
            raise ConnectionError("GDB stub not reachable; is EnableGDBServer on and a game running?")
        self.buf = b""
        self.cmd("?")

    def _recv(self) -> str:
        while True:
            i = self.buf.find(b"$")
            j = self.buf.find(b"#", i + 1)
            if i >= 0 and j >= 0 and len(self.buf) >= j + 3:
                pkt, self.buf = self.buf[i + 1:j], self.buf[j + 3:]
                self.sock.sendall(b"+")
                return pkt.decode()
            data = self.sock.recv(65536)
            if not data:
                raise EOFError("GDB stub closed the connection")
            self.buf += data

    def _send(self, payload: str) -> None:
        p = payload.encode()
        self.sock.sendall(b"$%s#%02x" % (p, sum(p) & 0xFF))

    def cmd(self, payload: str) -> str:
        self._send(payload)
        return self._recv()

    def regs(self) -> dict:
        raw = bytes.fromhex(self.cmd("g").replace("x", "0"))
        return dict(zip(REG_NAMES, struct.unpack("<%dI" % (len(raw) // 4), raw)))

    def mem(self, addr: int, size: int) -> bytes:
        out = b""
        while size:
            n = min(size, 0x400)
            out += bytes.fromhex(self.cmd(f"m{addr:x},{n:x}"))
            addr, size = addr + n, size - n
        return out

    def break_at(self, addr: int) -> None:
        self.cmd(f"Z0,{addr:x},4")

    def clear_break(self, addr: int) -> None:
        self.cmd(f"z0,{addr:x},4")

    def cont(self, timeout: float = 60) -> str:
        """Resume and wait for the next stop (breakpoint). Raises socket.timeout."""
        self._send("c")
        self.sock.settimeout(timeout)
        try:
            return self._recv()
        finally:
            self.sock.settimeout(5)

    def interrupt(self) -> str:
        """Halt a running target (Ctrl-C) and return its stop reply."""
        self.sock.sendall(b"\x03")
        return self._recv()

    def detach(self) -> None:
        # Wait for the stub's reply before closing, so the detach is
        # processed before the socket goes away.
        self._send("D")
        try:
            self.sock.settimeout(2)
            self._recv()
        except (OSError, EOFError):
            pass
        finally:
            self.sock.close()
