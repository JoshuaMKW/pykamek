from __future__ import annotations

import argparse
import re

from pathlib import Path
from typing import List

from addressmapper import AddressMapper
from exceptions import InvalidDataException
from linker import Linker
from kamek import KamekBinary
from versionmap import VersionMapper

def sorted_alphanumeric(l): 
    """ Sort the given iterable in the way that humans expect.""" 
    convert = lambda text: int(text) if text.isdigit() else text 
    alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', str(key))] 
    return sorted(l, key = alphanum_key)

class ElfHandler(Linker):
    def __init__(self, base: AddressMapper, files: [Path, List[Path]]):
        super().__init__(base)

        self.outputPath = None
        self.versionMap = None
        self.externals = {}

        if isinstance(files, Path):
            self.add_module(files)
        elif isinstance(files, str):
            self.add_module(Path(files))
        else:
            for obj in sorted_alphanumeric(files):
                obj = Path(obj)
                if obj.is_file():
                    self.add_module(obj)
                else:
                    for f in sorted_alphanumeric(obj.iterdir()):
                        if f.is_file:
                            self.add_module(f)

    def __repr__(self):
        return f"repr={vars(self)}"

    def __str__(self):
        return f"ELF module converter; {self.__repr__()}"

    @staticmethod
    def read_externals(file: str) -> dict:
        symbolDict = {}
        assignmentRegex = re.compile(r"^\s*([a-zA-Z0-9_<>,\-\$]+)\s*=\s*0x([a-fA-F0-9]+)\s*(#.*)?$")

        with open(file, "r") as f:
            for i, line in enumerate(f.readlines()):
                if line.strip() == "" or line.strip().startswith("#") or line.strip().startswith("//"):
                    continue

                try:
                    match = re.findall(assignmentRegex, line.strip())
                    _symbol = match[0][0]
                    _address = match[0][1]
                except IndexError:
                    raise InvalidDataException(f"Symbol definition {line.strip()} at line {i} is an invalid entry")

                try:
                    symbolDict[_symbol] = int(_address, 16)
                except ValueError:
                    raise InvalidDataException(f"Address {_address} at line {i} is not a hexadecimal number")

        return symbolDict

    def exec_jobs(self):
        pass

def main():
    parser = argparse.ArgumentParser("elftokuribo", description="ELF to Kuribo module converter")

    parser.add_argument("elf", help="ELF object file(s) and or folders of ELF object files", nargs="+")
    parser.add_argument("--dynamic", help="The module is dynamically relocated", action="store_true")
    parser.add_argument("--static", help="The module is statically located at ADDR", metavar="ADDR")
    parser.add_argument("--extern", help="External linker map", metavar="FILE")
    parser.add_argument("--versionmap", help="Version map for address translations", metavar="FILE")
    parser.add_argument("-d", "--dest", help="Destination path", metavar="FILE")

    args = parser.parse_args()

    if args.dynamic and args.static:
        parser.error("Args `--dynamic' and `--static' cannot be used together")
    elif not args.dynamic and not args.static:
        parser.error("Must provide either `--dynamic' or `--static' arguments")

    _externals = None
    _versionMap = None

    if args.dynamic:
        _baseAddr = None
    elif args.static:
        _baseAddr = int(args.static, 16)

    _externals = {}
    if args.extern:
        _externals = ElfHandler.read_externals(Path(args.extern).resolve())

    if args.versionmap:
        _versionMap = VersionMapper(Path(args.versionmap).resolve())
    else:
        _versionMap = VersionMapper()

    if args.dest:
        _dest = Path(args.dest).resolve()
    else:
        _dest = Path("build-$KV$.kmk").resolve()

    for versionKey in _versionMap.mappers:
        print(f"Linking version {versionKey}")

        elfConverter = ElfHandler(_versionMap.mappers[versionKey], args.elf)

        if _baseAddr:
            elfConverter.link_static(_externals, _baseAddr)
        else:
            elfConverter.link_dynamic(_externals)

        kb = KamekBinary()
        kb.load_from_linker(elfConverter)
        with open(str(_dest).replace("$KV$", versionKey), "wb") as kBinary:
            kBinary.write(KamekBinary.pack_from(elfConverter).getvalue())

    print("Finished execution")

if __name__ == "__main__":
    main()