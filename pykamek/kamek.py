from __future__ import annotations

from io import BytesIO
from pathlib import Path

from dolreader.dol import DolFile
from dolreader.section import TextSection

from exceptions import InvalidCommandException, InvalidOperationException
from ioreader import (read_sbyte, read_sint16, read_sint32, read_ubyte,
                      read_uint16, read_uint32, write_sbyte, write_sint16,
                      write_sint32, write_ubyte, write_uint16, write_uint32)
from kmcommands import RelocCommand
from kmhooks import KHook
from kmword import KWord
from linker import Linker


class KamekBinary(object):

    def __init__(self, f: str = None, baseAddr: int = 0x80000000):
        if f is not None:
            self.read_ppc_code(f)
        else:
            self.rawCode = BytesIO()

        self.baseAddr = baseAddr
        self.bssSize = KWord(0, KWord.Types.VALUE)
        self.sbssSize = KWord(0, KWord.Types.VALUE)
        self.sbss2Size = KWord(0, KWord.Types.VALUE)

        self.commands = {}
        self.hooks = []
        self.symbolSizes = {}
        self.mapper = None

    def __repr__(self) -> str:
        return f"repr={vars(self)}"

    def __str__(self) -> str:
        return f"Kamek binary; {self.__repr__()}"

    @property
    def codeSize(self):
        return len(self.rawCode.getbuffer())

    @staticmethod
    def pack_from(linker: Linker) -> BytesIO:
        kf = KamekBinary()
        kf.load_from_linker(linker)
        return kf.pack()

    def read_u8(self, address: int) -> int:
        self.seek(address - self.baseAddr.value)
        return read_ubyte(self.rawCode)

    def read_s8(self, address: int) -> int:
        self.seek(address - self.baseAddr.value)
        return read_sbyte(self.rawCode)

    def read_u16(self, address: int) -> int:
        self.seek(address - self.baseAddr.value)
        return read_uint16(self.rawCode)

    def read_s16(self, address: int) -> int:
        self.seek(address - self.baseAddr.value)
        return read_sint16(self.rawCode)

    def read_u32(self, address: int) -> int:
        self.seek(address - self.baseAddr.value)
        return read_uint32(self.rawCode)

    def read_s32(self, address: int) -> int:
        self.seek(address - self.baseAddr.value)
        return read_sint32(self.rawCode)

    def write_u8(self, address: int, val: int) -> int:
        self.seek(address - self.baseAddr.value)
        write_ubyte(self.rawCode, val)

    def write_s8(self, address: int, val: int) -> int:
        self.seek(address - self.baseAddr.value)
        write_sbyte(self.rawCode, val)

    def write_u16(self, address: int, val: int) -> int:
        self.seek(address - self.baseAddr.value)
        write_uint16(self.rawCode, val)

    def write_s16(self, address: int, val: int) -> int:
        self.seek(address - self.baseAddr.value)
        write_sint16(self.rawCode, val)

    def write_u32(self, address: int, val: int) -> int:
        self.seek(address - self.baseAddr.value)
        write_uint32(self.rawCode, val)

    def write_s32(self, address: int, val: int) -> int:
        self.seek(address - self.baseAddr.value)
        write_sint32(self.rawCode, val)

    def seek(self, where: int, whence: int = 0):
        self.rawCode.seek(where, whence)

    def read_ppc_code(self, f: Path):
        self.rawCode = BytesIO(f.read_bytes())

    def contains(self, addr: KWord) -> bool:
        return addr >= self.baseAddr and addr < (self.baseAddr + self.codeSize)

    def get_symbol_size(self, addr: KWord) -> int:
        return self.symbolSizes[addr]

    def load_from_linker(self, linker: Linker):
        if self.codeSize > 0:
            raise InvalidOperationException("This Kamek binary already has stuff in it")
        
        self.mapper = linker

        #Extract only code/data sections
        linker._memory.seek(linker.outputStart.value - linker.baseAddress.value)
        
        self.rawCode = BytesIO(linker._memory.read(linker.outputSize.value))

        self.baseAddr = linker.baseAddress
        self.bssSize = linker.bssSize
        self.sbssSize = linker.sbssSize
        self.sbss2Size = linker.sbss2Size
        
        for _key in linker._symbolSizes:
            self.symbolSizes[_key] = linker._symbolSizes[_key]

        self.add_relocs_as_commands(linker._fixups)

        for cmd in linker._kamekHooks:
            self.apply_hook(cmd)

        self.apply_static_commands()

    def add_relocs_as_commands(self, relocs: list):
        for rel in relocs:
            if rel.source in self.commands:
                raise InvalidOperationException(f"Duplicate commands for address {rel.source.value:X}")

            self.commands[rel.source] = RelocCommand(rel.source, rel.dest, rel.type)

    def apply_hook(self, hookData):
        hook = KHook.create(hookData, self.mapper)
        for cmd in hook.commands:
            if cmd.address in self.commands:
                raise InvalidOperationException(f"Duplicate commands for address {cmd.address.value:X}")
            
            self.commands[cmd.address] = cmd
        self.hooks.append(hook)

    def apply_static_commands(self):
        _original = self.commands
        self.commands = {}

        for cmd in _original.values():
            if not cmd.apply(self):
                self.commands[cmd.address] = cmd

    def pack(self) -> BytesIO:
        _packedBinary = BytesIO()
        _packedBinary.write(b"Kamek\x00\x00\x01")
        write_uint32(_packedBinary, self.bssSize.value)
        write_uint32(_packedBinary, self.codeSize)

        _packedBinary.write(self.rawCode.getvalue())

        for _key in self.commands:
            cmd = (self.commands[_key].id << 24) & 0xFFFFFFFF
            address = self.commands[_key].address

            if address.is_relative_addr():
                if address > 0xFFFFFF:
                    raise InvalidCommandException(f"Given address {address} is too high for packed command")

                write_uint32(_packedBinary, cmd | address.value)
            else:
                write_uint32(_packedBinary, cmd | 0xFFFFFE)
                write_uint32(_packedBinary, address.value)
            
            self.commands[_key].write_arguments(_packedBinary)

        _packedBinary.seek(0)
        return _packedBinary

    def pack_riivo(self) -> str:
        pass

    def pack_gecko_codes(self) -> str:
        pass

    def apply_to_dol(self, dol: DolFile):
        if self.baseAddr.type == KWord.Types.RELATIVE:
            raise InvalidOperationException("Cannot pack a dynamically linked binary into a DOL")

        dol.append_section(TextSection(self.baseAddr.value, self.rawCode))

        for _key in self.commands:
            self.commands[_key].apply_to_dol(dol)

