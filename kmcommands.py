from __future__ import annotations

from io import BytesIO

from dolreader.dol import DolFile

from elfenums import ELFFlags
from exceptions import InvalidOperationException
from ioreader import (read_ubyte, read_uint16, read_uint32, write_ubyte,
                      write_uint16, write_uint32)
from kmword import KWord


class Command(object):
    class KCmdID:
        Null = 0

        # these deliberately match the ELF relocations
        Addr32 = 1
        Addr16Lo = 4
        Addr16Hi = 5
        Addr16Ha = 6
        Rel24 = 10

        # these are new
        WritePointer = 1 # same as Addr32 on purpose
        Write32 = 32
        Write16 = 33
        Write8 = 34
        CondWritePointer = 35
        CondWrite32 = 36
        CondWrite16 = 37
        CondWrite8 = 38

        Branch = 64
        BranchLink = 65

    def __init__(self, kId: KCmdID, address: KWord):
        self.id = kId
        self.address = address

class BranchCommand(Command):
    def __init__(self, source: KWord, target: KWord, isLink: bool):
        kId = Command.KCmdID.BranchLink if isLink else Command.KCmdID.Branch
        super().__init__(kId, source)
        self.target = target

    def __repr__(self) -> str:
        return f"repr={vars(self)}"

    def __str__(self) -> str:
        return f"Branch Command; {self.__repr__()}"

    def write_arguments(self, io: BytesIO):
        self.target.assert_not_ambiguous()
        write_uint32(io, self.target.value)

    def is_equal_reloc_types(self) -> bool:
        return self.address.type == self.target.type

    def is_equal_reloc_absolute(self) -> bool:
        return self.is_equal_reloc_types() and self.target.is_absolute_addr()

    def is_equal_reloc_relative(self) -> bool:
        return self.is_equal_reloc_types() and self.target.is_relative_addr()

    def apply(self, f: "KamekBinary"):
        if self.is_equal_reloc_absolute() and f.contains(self.address):
            f.write_u32(self.address.value, self._generate_instruction())

    def pack_riivo(self) -> str:
        raise NotImplementedError()

    def pack_gecko_codes(self) -> list:
        raise NotImplementedError()

    def apply_to_dol(self, dol: DolFile):
        self.address.assert_absolute()
        self.target.assert_absolute()

        dol.seek(self.address.value)
        write_uint32(dol, self._generate_instruction())

    def _generate_instruction(self) -> int:
        delta = self.target - self.address
        insn = 0x48000001 if self.id == Command.KCmdID.BranchLink else 0x48000000
        return insn | (delta.value & 0x3FFFFFC)

class PatchExitCommand(Command):
    def __init__(self, source: KWord, target: KWord):
        super().__init__(Command.KCmdID.Branch, source)
        self.target = target
        self.endAddress = KWord(0, KWord.Types.ABSOLUTE)

    def __repr__(self) -> str:
        return f"repr={vars(self)}"

    def __str__(self) -> str:
        return f"Exit Patch Command; {self.__repr__()}"

    def write_arguments(self, io: BytesIO):
        self.endAddress.assert_not_ambiguous()
        self.target.assert_not_ambiguous()
        write_uint32(io, self.endAddress.value)
        write_uint32(io, self.target.value)

    def is_equal_reloc_types(self) -> bool:
        return self.address.type == self.target.type == self.endAddress.type

    def is_equal_reloc_absolute(self) -> bool:
        return self.is_equal_reloc_types() and self.target.is_absolute_addr()

    def is_equal_reloc_relative(self) -> bool:
        return self.is_equal_reloc_types() and self.target.is_relative_addr()

    def apply(self, f: "KamekBinary") -> bool:
        funcSize = f.get_symbol_size(self.address)
        funcEnd = self.address + (funcSize - 4)

        if funcSize < 4:
            raise InvalidOperationException("Queried function is too small")

        if f.read_u32(funcEnd) != 0x4E800020:
            raise InvalidOperationException("Function does not end in blr")

        instrLoc = self.address
        while instrLoc < funcEnd:
            insn = f.read_u32(instrLoc)
            if (insn & 0xFC00FFFF == 0x4C000020):
                raise InvalidOperationException("Function contains a return partway through")
            instrLoc += 4

        self.endAddress = funcEnd
        if self.is_equal_reloc_absolute() and f.contains(self.address):
            f.write_u32(self.endAddress.value, self._generate_instruction())
            return True
        else:
            return False

    def pack_riivo(self) -> str:
        raise NotImplementedError()

    def pack_gecko_codes(self) -> list:
        raise NotImplementedError()

    def apply_to_dol(self):
        raise NotImplementedError()

    def _generate_instruction(self) -> int:
        delta = self.target - self.address
        insn = 0x48000001 if self.id == Command.KCmdID.BranchLink else 0x48000000
        return insn | (delta.value & 0x3FFFFFC)
     
class WriteCommand(Command):
    class Type:
        Pointer = 1
        Value32 = 2
        Value16 = 3
        Value8 = 4

    def __init__(self, address: KWord, value: KWord, valueType: Type, original: KWord = None):
        super().__init__(self.id_from_type(valueType, original != None), address)
        self.value = value
        self.valueType = valueType

        if original:
            self.original = original
        else:
            self.original = None

    def __repr__(self) -> str:
        return f"repr={vars(self)}"
    
    def __str__(self) -> str:
        return f"Write Command; {self.__repr__()}"

    @staticmethod
    def id_from_type(_type: Type, isConditional: bool) -> Type:
        if isConditional:
            if _type == WriteCommand.Type.Pointer:
                return Command.KCmdID.CondWritePointer
            elif _type == WriteCommand.Type.Value32:
                return Command.KCmdID.CondWrite32
            elif _type == WriteCommand.Type.Value16:
                return Command.KCmdID.CondWrite16
            elif _type == WriteCommand.Type.Value8:
                return Command.KCmdID.CondWrite8
        else:
            if _type == WriteCommand.Type.Pointer:
                return Command.KCmdID.WritePointer
            elif _type == WriteCommand.Type.Value32:
                return Command.KCmdID.Write32
            elif _type == WriteCommand.Type.Value16:
                return Command.KCmdID.Write16
            elif _type == WriteCommand.Type.Value8:
                return Command.KCmdID.Write8

        raise NotImplementedError(f"Unimplemented command type {_type} specified")

    def write_arguments(self, io: BytesIO):
        if self.valueType == WriteCommand.Type.Pointer:
            self.value.assert_not_ambiguous()
        else:
            self.value.assert_value()

        write_uint32(io, self.value.value)
        
        if self.original is not None:
            self.original.assert_not_relative()
            write_uint32(io, self.original.value)

    def apply(self, f: "KamekBinary") -> bool:
        return False

    def pack_riivo(self) -> str:
        self.address.assert_absolute()
        if self.valueType == WriteCommand.Type.Pointer:
            self.value.assert_absolute()
        else:
            self.value.assert_value()

        if self.original is not None:
            self.original.assert_not_relative()

            if self.valueType == WriteCommand.Type.Value8:
                return f"<memory offset='0x{self.address:X8}' value='{self.value:X2}' original='{self.original:X2}' />"
            elif self.valueType == WriteCommand.Type.Value16:
                return f"<memory offset='0x{self.address:X8}' value='{self.value:X4}' original='{self.original:X4}' />"
            elif self.valueType == WriteCommand.Type.Value32:
                return f"<memory offset='0x{self.address:X8}' value='{self.value:X8}' original='{self.original:X8}' />"
            elif self.valueType == WriteCommand.Type.Pointer:
                return f"<memory offset='0x{self.address:X8}' value='{self.value:X8}' original='{self.original:X8}' />"

        else:
            if self.valueType == WriteCommand.Type.Value8:
                return f"<memory offset='0x{self.address:X8}' value='{self.value:X2}' />"
            elif self.valueType == WriteCommand.Type.Value16:
                return f"<memory offset='0x{self.address:X8}' value='{self.value:X4}' />"
            elif self.valueType == WriteCommand.Type.Value32:
                return f"<memory offset='0x{self.address:X8}' value='{self.value:X8}' />"
            elif self.valueType == WriteCommand.Type.Pointer:
                return f"<memory offset='0x{self.address:X8}' value='{self.value:X8}' />"

        raise InvalidOperationException(f"Invalid command type {self.valueType} specified")
    
    def pack_gecko_codes(self) -> list:
        self.address.assert_absolute()
        if self.valueType == WriteCommand.Type.Pointer:
            self.value.assert_absolute()
        else:
            self.value.assert_value()

        if self.original is not None:
            raise NotImplementedError("Conditional writes not yet supported for gecko")
        elif self.address >= 0x90000000:
            raise NotImplementedError("MEM2 writes not yet supported for gecko")

        code = ((self.address & 0x1FFFFFF) << 32) | self.value

        if self.valueType == WriteCommand.Type.Value16:
            return list(code | (0x2000000 << 32))
        elif self.valueType == WriteCommand.Type.Value32:
            return list(code | (0x4000000 << 32))
        elif self.valueType == WriteCommand.Type.Pointer:
            return list(code | (0x4000000 << 32))

        raise InvalidOperationException(f"Invalid command type {self.valueType} specified")

    def apply_to_dol(self, dol: DolFile):
        self.address.assert_absolute()
        if self.valueType == WriteCommand.Type.Pointer:
            self.value.assert_absolute()
        else:
            self.value.assert_value()

        if self.original is not None:
            shouldPatch = False

            if self.valueType == WriteCommand.Type.Value8:
                dol.seek(self.address.value)
                shouldPatch = self.original == read_ubyte(dol)
            elif self.valueType == WriteCommand.Type.Value16:
                dol.seek(self.address.value)
                shouldPatch = self.original == read_uint16(dol)
            elif self.valueType == WriteCommand.Type.Value32:
                dol.seek(self.address.value)
                shouldPatch = self.original == read_uint32(dol)
            elif self.valueType == WriteCommand.Type.Pointer:
                dol.seek(self.address.value)
                shouldPatch = self.original == read_uint32(dol)
            
            if not shouldPatch:
                return

        if self.valueType == WriteCommand.Type.Value8:
            dol.seek(self.address.value)
            write_ubyte(dol, self.value.value)
        elif self.valueType == WriteCommand.Type.Value16:
            dol.seek(self.address.value)
            write_uint16(dol, self.value.value)
        elif self.valueType == WriteCommand.Type.Value32:
            dol.seek(self.address.value)
            write_uint32(dol, self.value.value)
        elif self.valueType == WriteCommand.Type.Pointer:
            dol.seek(self.address.value)
            write_uint32(dol, self.value.value)


class RelocCommand(Command):
    def __init__(self, source: KWord, target: KWord, reloc: ELFFlags.Reloc):
        super().__init__(reloc, source)
        self.target = target

    def __repr__(self) -> str:
        return f"repr={vars(self)}"
    
    def __str__(self) -> str:
        return f"Relocation Command; {self.__repr__()}"

    def is_equal_reloc_types(self) -> bool:
        return self.address.type == self.target.type

    def is_equal_reloc_absolute(self) -> bool:
        return self.is_equal_reloc_types() and self.target.is_absolute_addr()

    def is_equal_reloc_relative(self) -> bool:
        return self.is_equal_reloc_types() and self.target.is_relative_addr()

    def write_arguments(self, io: BytesIO):
        self.target.assert_not_ambiguous()
        write_uint32(io, self.target.value)

    def apply(self, f: "KamekBinary") -> bool:
        if self.id == Command.KCmdID.Rel24:
            if self.is_equal_reloc_types() and not self.target.is_value():
                delta = self.target - self.address

                insn = (delta & 0x3FFFFFC) | (f.read_u32(self.address.value) & 0xFC000003)
                f.write_u32(self.address.value, insn.value)
                return True
 
        elif self.id == Command.KCmdID.Addr32:
            if self.target.is_absolute_addr():
                f.write_u32(self.address.value, self.target.value)
                return True

        elif self.id == Command.KCmdID.Addr16Lo:
            if self.target.is_absolute_addr():
                f.write_u16(self.address.value, self.target.value & 0xFFFF)
                return True

        elif self.id == Command.KCmdID.Addr16Hi:
            if self.target.is_absolute_addr():
                f.write_u16(self.address.value, (self.target.value >> 16) & 0xFFFF)
                return True

        elif self.id == Command.KCmdID.Addr16Ha:
            if self.target.is_absolute_addr():
                aTarget = ((self.target.value >> 16) + 1) & 0xFFFF if (self.target.value >> 16) & 0x8000 != 0 else (self.target.value >> 16) & 0xFFFF
                f.write_u16(self.address.value, aTarget)
                return True

        else:
            raise NotImplementedError("Unrecognized relocation type")

        return False
        

    def pack_riivo(self) -> str:
        raise NotImplementedError()

    def pack_gecko_codes(self) -> list:
        raise NotImplementedError()

    def apply_to_dol(self, dol: DolFile):
        self.address.assert_absolute()
        self.target.assert_absolute()

        if self.id == Command.KCmdID.Rel24:
            delta = self.target - self.address

            dol.seek(self.address.value)
            insn = (delta & 0x3FFFFFC) | (read_uint32(dol) & 0xFC000003)
            dol.seek(self.address.value)
            write_uint32(dol, insn.value)
 
        elif self.id == Command.KCmdID.Addr32:
            dol.seek(self.address.value)
            write_uint32(dol, self.target.value)

        elif self.id == Command.KCmdID.Addr16Lo:
            dol.seek(self.address.value)
            write_uint32(dol, self.target.value & 0xFFFF)

        elif self.id == Command.KCmdID.Addr16Hi:
            dol.seek(self.address.value)
            write_uint32(dol, (self.target.value >> 16) & 0xFFFF)

        elif self.id == Command.KCmdID.Addr16Ha:
            aTarget = ((self.target.value >> 16) + 1) & 0xFFFF if (self.target.value >> 16) & 0x8000 != 0 else (self.target.value >> 16) & 0xFFFF
            dol.seek(self.address.value)
            write_uint32(dol, aTarget)

        else:
            raise NotImplementedError("Unrecognized relocation type")
