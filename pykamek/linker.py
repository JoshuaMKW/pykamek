from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Tuple

from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import (ELFFile, Section, StringTableSection,
                                  SymbolTableIndexSection, SymbolTableSection)
from elftools.elf.relocation import RelocationSection

from pykamek.addressmapper import AddressMapper
from pykamek.elfenums import ELFFlags
from pykamek.exceptions import (AlreadyExistsException, AlreadyLinkedException,
                        InvalidDataException, InvalidOperationException,
                        InvalidTableLinkageException)
from pykamek.ioreader import (read_sbyte, read_sint16, read_sint32, read_ubyte,
                      read_uint16, read_uint32, write_sbyte, write_sint16,
                      write_sint32, write_ubyte, write_uint16, write_uint32)
from pykamek.kmhooks import HookData
from pykamek.kmword import KWord


class Linker(AddressMapper):

    class Symbol(object):
        def __init__(self, address: KWord, size: int = 0, isWeak: bool = False):
            self.address = KWord(address, address.type)
            self.size = size
            self.isWeak = isWeak

        def __repr__(self) -> str:
            return f"repr={vars(self)}"

        def __str__(self) -> str:
            return f"Symbol container; {self.__repr__()}"

    class RelocFixup(object):
        def __init__(self, reloctype: ELFFlags.Reloc, source: KWord, dest: KWord):
            self.type = reloctype
            self.source = KWord(source, source.type)
            self.dest = KWord(dest, dest.type)

        def __repr__(self) -> str:
            return f"repr=({self.type}, {self.source.value:X}, {self.dest.value:X})"

        def __str__(self) -> str:
            return f"Relocation handler; {self.__repr__()}"

    def __init__(self, base: AddressMapper):
        super().__init__(base)
        self.baseAddress = KWord(0x80000000, KWord.Types.ABSOLUTE)
        self.outputStart, self.outputEnd = KWord(0, KWord.Types.ABSOLUTE), KWord(0, KWord.Types.ABSOLUTE)
        self.bssStart, self.bssEnd = KWord(0, KWord.Types.ABSOLUTE), KWord(0, KWord.Types.ABSOLUTE)
        self.kamekStart, self.kamekEnd = KWord(0, KWord.Types.ABSOLUTE), KWord(0, KWord.Types.ABSOLUTE)

        # SECTIONS

        self._linked = False
        self._modules = {}
        self._binaries = []
        self._sectionBases = {}
        self._location = 0
        self._memory = BytesIO()

        # SYMBOLS

        self._globalSymbols = {}
        self._localSymbols = {}
        self._symbolTableContents = {}
        self._externSymbols = {}
        self._symbolSizes = {}

        # RELOCATIONS

        self._fixups = []

        # KAMEK HOOKS

        self._kamekRelocs = {}
        self._kamekHooks = []

        # OTHER

        self._shndx_sections= {}

    def __repr__(self) -> str:
        return f"repr={vars(self)}"

    def __str__(self) -> str:
        return f"Module linker; {self.__repr__()}"

    def __iadd__(self, elf: Path):
        print(f"Adding {elf} as object")
        self._modules[elf] = ELFFile(BytesIO(elf.read_bytes()))

    def __isub__(self, elf: Path):
        print(f"Removing {elf} from object list")
        self._modules.pop(elf, f"{elf} does not exist in the current container")

    @property
    def outputSize(self) -> int:
        return self.outputEnd - self.outputStart

    @property
    def bssSize(self) -> int:
        return self.bssEnd - self.bssStart

    @property
    def modules(self) -> Tuple[Path, ELFFile]:
        for _key in self._modules:
            yield _key, self._modules[_key]

    # """ MODULES """

    def add_module(self, elf: Path):
        if self._linked:
            raise AlreadyLinkedException("This linker has already been linked")
        if elf in self._modules.keys():
            raise AlreadyExistsException("This module is already part of this linker")

        self.__iadd__(elf)

    def clear_modules(self):
        self._modules = {}

    def remove_module(self, elf: Path):
        self.__isub__(elf)

    def pop_module(self, elf: Path):
        return self._modules.pop(elf)

    # """ LINKING """

    def link_static(self, symbolData: dict, baseAddr: int = None):
        if baseAddr:
            self.baseAddress = KWord(self.remap(baseAddr), KWord.Types.ABSOLUTE)

        self._do_link(symbolData)

    def link_dynamic(self, symbolData: dict):
        self.baseAddress = KWord(0, KWord.Types.RELATIVE)
        self._do_link(symbolData)

    def _do_link(self, symbolData: list):
        if self._linked:
            raise AlreadyLinkedException("This linker has already been linked")

        self._linked = True

        for key in symbolData:
            self._externSymbols[key] = self.remap(symbolData[key])

        self._collect_sections()
        self._build_symbol_tables()
        self._process_relocations()
        self._process_hooks()

    # """ SECTIONS """

    def _import_sections(self, prefix: str, alignEnd: int = 4, padding: int = 0):
        imported = False
        baseAddress = self._location.value

        for elf in self._modules.values():
            for section in elf.iter_sections():
                if not section.name.startswith(prefix):
                    continue

                self._sectionBases[self.__get_section_key(section)] = KWord(self._location, KWord.Types.ABSOLUTE)
                sectionPadding = b"\x00" * (4 - (self._location.value % 4))
                self._location += (section.data_size + 3) & -4
                self._binaries.append(BytesIO(section.data() + sectionPadding))
                imported = True
        
        if imported:
            self._externSymbols[f"_f_{prefix[1:]}"] = baseAddress
            self._externSymbols[f"_e_{prefix[1:]}"] = self._location.value - padding
            self._location += padding
            if alignEnd > 0 and self._location.value % alignEnd != 0:
                padlen = alignEnd - (self._location.value % alignEnd) + padding
                self._location = (self._location + (alignEnd-1)) & -alignEnd
                self._binaries.append(BytesIO(b"\x00" * padlen))


    def _collect_sections(self):
        self._location = KWord(self.baseAddress, KWord.Types.ABSOLUTE)
        self.outputStart.value = self._location.value

        self._import_sections(".init")
        self._import_sections(".fini")
        self._import_sections(".text")
        self._import_sections(".ctors", alignEnd=32, padding=4)
        self._import_sections(".dtors", alignEnd=32, padding=4)
        self._import_sections(".rodata", alignEnd=32)
        self._import_sections(".data", alignEnd=32)

        self.outputEnd.value = self._location.value

        self.bssStart.value = self.outputEnd.value
        self._import_sections(".bss", alignEnd=32)
        self.bssEnd.value = self._location.value

        self.kamekStart.value = self._location.value
        self._import_sections(".kamek")
        self.kamekEnd.value = self._location.value

        for binary in self._binaries:
            self._memory.write(binary.getvalue())

    # """ SYMBOLS """

    def _resolve_symbol(self, elfpath: str, name: str) -> Linker.Symbol:
        _locals = self._localSymbols[elfpath]
        if name in _locals:
            return _locals[name]
        elif name in self._globalSymbols:
            return self._globalSymbols[name]
        elif name in self._externSymbols:
            return Linker.Symbol(KWord(self._externSymbols[name], KWord.Types.ABSOLUTE))

        raise InvalidDataException(f"Undefined symbol \"{name}\"")

    def _build_symbol_tables(self):
        for path, elf in self.modules:
            _locals = {}

            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue

                strTabIdx = section.header["sh_link"]
                if strTabIdx <= 0 or strTabIdx >= elf.num_sections():
                    raise InvalidTableLinkageException("Symbol table is not linked to a string table")

                strTab = elf.get_section(strTabIdx)

                self._symbolTableContents[self.__get_section_key(section)] = self._parse_symbol_table(path, elf, section, strTab, _locals)

    def _parse_symbol_table(self, elfpath: str, elf: ELFFile, symTab: SymbolTableSection, strTab: StringTableSection, _locals: dict) -> list:
        if symTab.header["sh_entsize"] != 16:
            raise InvalidDataException("Invalid symbol table format (sh_entsize != 16)")
        if not isinstance(strTab, StringTableSection):
            raise InvalidDataException("String table does not have type SHT_STRTAB")

        _symbolNames = []

        for symbol in symTab.iter_symbols():
            name = symbol.name
            st_value = symbol["st_value"]
            st_size = symbol["st_size"]
            st_info = symbol["st_info"]
            st_shndx = symbol["st_shndx"]
            
            _symbolNames.append(name)

            if len(name) == 0 or st_shndx == "SHN_UNDEF":
                continue


            # What location is this referencing?
            if isinstance(st_shndx, int): # Reference
                refSection = elf.get_section(st_shndx)
                _refkey = self.__get_section_key(refSection)

                if _refkey not in self._sectionBases:
                    continue # Skip past unwanted symbols

                addr = KWord(self._sectionBases[_refkey] + st_value,
                             self._sectionBases[_refkey].type)
            elif st_shndx == "SHN_ABS": # Absolute symbol
                refSection = None
                addr = KWord(st_value, KWord.Types.ABSOLUTE)
            else:
                raise InvalidDataException("Unknown section index found in symbol table")

            if st_info["bind"] == "STB_LOCAL":
                if name in _locals:
                    raise InvalidDataException(f"Redefinition of local symbol {name}")
                
                _locals[name] = Linker.Symbol(addr, st_size)
                self._symbolSizes[addr] = st_size

            elif st_info["bind"] == "STB_GLOBAL":
                if name in self._globalSymbols and not self._globalSymbols[name].isWeak:
                    raise InvalidDataException(f"Redefinition of global symbol {name}")

                self._globalSymbols[name] = Linker.Symbol(addr, st_size)
                self._symbolSizes[addr] = st_size
                
            elif st_info["bind"] == "STB_WEAK":
                if name not in self._globalSymbols:
                    self._globalSymbols[name] = Linker.Symbol(addr, st_size, isWeak=True)
                    self._symbolSizes[addr] = st_size
            
        self._localSymbols[elfpath] = _locals
        return _symbolNames

    # """ RELOCATIONS """

    def _process_relocations(self):
        for _elfkey in self._modules:
            elf = self._modules[_elfkey]
            for _ in [s for s in elf.iter_sections() if s.header["sh_type"] == "SHT_REL"]:
                raise InvalidDataException("OH CRAP ;P")

            for section in [s for s in elf.iter_sections() if s.header["sh_type"] == "SHT_RELA"]:
                if section.header["sh_info"] <= 0 or section.header["sh_info"] >= elf.num_sections():
                    raise InvalidDataException("Rela table is not linked to a section")
                if section.header["sh_link"] <= 0 or section.header["sh_link"] >= elf.num_sections():
                    raise InvalidDataException("Rela table is not linked to a symbol table")

                affected = elf.get_section(section.header["sh_info"])
                symTab = elf.get_section(section.header["sh_link"])
                
                self._process_rela_section(_elfkey, elf, section, affected, symTab)

    def _process_rela_section(self, elfpath: str, elf: ELFFile, relocs: RelocationSection, section: Section, symTab: SymbolTableSection):
        if relocs.header["sh_entsize"] != 12:
            raise InvalidDataException("Invalid relocs format (sh_entsize != 12)")
        if not isinstance(symTab, SymbolTableSection):
            raise InvalidDataException("Symbol table does not have type SHT_SYMTAB")

        for relocation in relocs.iter_relocations():
            reloc = relocation["r_info"] & 0xFF
            symIndex = relocation["r_info"] >> 8
            _symkey = self.__get_section_key(section)

            if symIndex == 0:
                raise InvalidDataException("Linking to undefined symbol")
            elif _symkey not in self._sectionBases:
                continue

            symName = self._symbolTableContents[self.__get_section_key(symTab)][symIndex]

            source = KWord(self._sectionBases[_symkey].value + relocation["r_offset"], KWord.Types.ABSOLUTE)
            dest = KWord(self._resolve_symbol(elfpath, symName).address.value + relocation["r_addend"], KWord.Types.ABSOLUTE)

            if not self._kamek_use_reloc(reloc, source, dest):
                self._fixups.append(Linker.RelocFixup(reloc, source, dest))

    # """ KAMEK HOOKS """

    def _kamek_use_reloc(self, _type: ELFFlags.Reloc, source: KWord, dest: KWord):
        if source < self.kamekStart or source >= self.kamekEnd:
            return False
        elif _type != ELFFlags.Reloc.R_PPC_ADDR32:
            raise InvalidOperationException("Unsupported relocation type in the Kamek hook data section")

        self._kamekRelocs[source] = dest
        return True

    def _process_hooks(self):
        for _elfkey in self._modules:
            for _symbolkey in self._localSymbols[_elfkey]:
                if _symbolkey.startswith("_kHook"):
                    cmdAddr = self._localSymbols[_elfkey][_symbolkey].address

                    self._memory.seek(cmdAddr.value - self.baseAddress.value)
                    argCount = read_uint32(self._memory)
                    _type = read_uint32(self._memory)
                    args = []

                    for i in range(argCount):
                        argAddr = cmdAddr + (8 + (i << 2))
                        if argAddr in self._kamekRelocs:
                            args.append(self._kamekRelocs[argAddr])
                        else:
                            self._memory.seek(argAddr.value - self.baseAddress.value)
                            args.append(KWord(read_uint32(self._memory), KWord.Types.VALUE))
                    self._kamekHooks.append(HookData(_type, args))

    @staticmethod
    def __get_section_key(section) -> str:
        return "".join([str(data) for data in section.header.values()])

