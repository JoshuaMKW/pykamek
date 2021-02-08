__version__ = "1.0.2"
__author__ = 'JoshuaMK'
__credits__ = 'Treeki'

import re

from argparse import ArgumentParser
from io import BytesIO
from pathlib import Path
from typing import List

from dolreader.dol import DolFile

from pykamek import __version__
from pykamek.addressmapper import AddressMapper
from pykamek.exceptions import InvalidDataException
from pykamek.linker import Linker
from pykamek.kamek import KamekBinary
from pykamek.versionmap import VersionMapper

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

def main(args: list):
    parser = ArgumentParser(f"pykamek {__version__}", description="ELF to Kuribo module converter")

    parser.add_argument("elf", help="ELF object file(s) and or folders of ELF object files", nargs="+")
    parser.add_argument("--dynamic", help="The module is dynamically relocated", action="store_true")
    parser.add_argument("--static", help="The module is statically located at ADDR", metavar="ADDR")
    parser.add_argument("--output-kamek", help="File to output Kamek Binary", metavar="FILE")
    parser.add_argument("--output-riiv", help="File to output riivolution XML", metavar="FILE")
    parser.add_argument("--output-gecko", help="File to output gecko code", metavar="FILE")
    parser.add_argument("--output-code", help="File to output raw code", metavar="FILE")
    parser.add_argument("--input-dol", help="Input DOL file", metavar="FILE")
    parser.add_argument("--output-dol", help="File to output patched DOL", metavar="FILE")
    parser.add_argument("--extern", help="External linker map", metavar="FILE")
    parser.add_argument("--versionmap", help="Version map for address translations", metavar="FILE")

    args = parser.parse_args(args)

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

    _outputKamekPath = None
    _outputRiivPath = None
    _outputGeckoPath = None
    _outputCodePath = None
    _inputDolPath = None
    _outputDolPath = None

    if args.output_kamek:
        _outputKamekPath = Path(args.output_kamek).resolve()
    if args.output_riiv:
        _outputRiivPath = Path(args.output_riiv).resolve()
    if args.output_gecko:
        _outputGeckoPath = Path(args.output_gecko).resolve()
    if args.output_code:
        _outputCodePath = Path(args.output_code).resolve()
    if args.input_dol:
        _inputDolPath = Path(args.input_dol).resolve()
    if args.output_dol:
        _outputDolPath = Path(args.output_dol).resolve()

    if (_outputKamekPath is None and
        _outputRiivPath is None and
        _outputGeckoPath is None and
        _outputCodePath is None and
        _outputDolPath is None
        ):
        parser.error("No output path(s) specified")

    if _inputDolPath is None and _outputDolPath:
        parser.error("Input DOL path not specified")

    for versionKey in _versionMap.mappers:
        print(f"Linking version {versionKey}")

        elfConverter = ElfHandler(_versionMap.mappers[versionKey], args.elf)

        if _baseAddr:
            elfConverter.link_static(_externals, _baseAddr)
        else:
            elfConverter.link_dynamic(_externals)

        kb = KamekBinary()
        kb.load_from_linker(elfConverter)
        if _outputKamekPath:
            with open(str(_outputKamekPath).replace("$KV$", versionKey), "wb") as kBinary:
                kBinary.write(kb.pack().getvalue())
        if _outputRiivPath:
            with open(str(_outputRiivPath).replace("$KV$", versionKey), "w") as kBinary:
                kBinary.write(kb.pack_riivo())
        if _outputGeckoPath:
            with open(str(_outputGeckoPath).replace("$KV$", versionKey), "w") as kBinary:
                kBinary.write(kb.pack_gecko_codes())
        if _outputCodePath:
            with open(str(_outputCodePath).replace("$KV$", versionKey), "wb") as kBinary:
                kBinary.write(kb.rawCode.getvalue())

        if _outputDolPath:
            dol = DolFile(BytesIO(_inputDolPath.read_bytes()))
            kb.apply_to_dol(dol)

            outPath = str(_outputDolPath).replace("$KV$", versionKey)

            with open(outPath, "wb") as outDol:
                dol.save(outDol)

    print("Finished execution")