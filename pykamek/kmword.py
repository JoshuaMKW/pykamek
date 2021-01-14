from __future__ import annotations

from exceptions import InvalidOperationException

class KWord(object):
    class Types:
        VALUE = 1
        ABSOLUTE = 2
        RELATIVE = 3

    def __init__(self, value: int = 0, _type: KWord.Types = Types.VALUE, signed: bool = False):
        """
        Returns a 32bit clamped `KWord` object

        --Arguments--

        value; 32bit sized integer, range is -0x7FFFFFFF -> 0xFFFFFFFF
        _type; Context of this value, can be either `VALUE`, `RELATIVE`, or `ABSOLUTE`
        signed; Is this KWord signed or unsigned - NOTE: Is automatically unsigned if value is > 0x7FFFFFFF
        """

        if isinstance(value, KWord):
            value = value.value
        else:
            value = int(value)

        self.type = _type
        self.signed = signed and value < 0x7FFFFFFF

        if value > 0xFFFFFFFF or value < -0x7FFFFFFF:
            raise ValueError(f"'{value}' is too extreme for a 32bit number")

        self._value = self.__clamp(value)

    @property
    def value(self) -> int:
        return self.__expand(self._value)
        
    @value.setter
    def value(self, value: int):
        self._value = self.__clamp(value)

    def __repr__(self) -> str:
        return f"repr=(Value: {self.__expand(self._value)}, {vars(self)})"

    def __str__(self) -> str:
        return f"Kamek extended integer; {self.__repr__()}"

    def __add__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value + self.__retrieve_value(other)), self.type)

    def __sub__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value - self.__retrieve_value(other)), self.type)

    def __mul__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value * self.__retrieve_value(other)), self.type)

    def __truediv__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value / self.__retrieve_value(other)), self.type)

    def __floordiv__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value // self.__retrieve_value(other)), self.type)

    def __mod__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value % self.__retrieve_value(other)), self.type)

    def __pow__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value ** self.__retrieve_value(other)), self.type)

    def __rshift__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value >> self.__retrieve_value(other)), self.type)

    def __lshift__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value << self.__retrieve_value(other)), self.type)

    def __and__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value & self.__retrieve_value(other)), self.type)

    def __or__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value | self.__retrieve_value(other)), self.type)

    def __xor__(self, other: KWord) -> KWord: 
        return KWord(self.__clamp(self.value ^ self.__retrieve_value(other)), self.type)

    def __lt__(self, other: KWord) -> bool: 
        return self.value < self.__retrieve_value(other)

    def __gt__(self, other: KWord) -> bool: 
        return self.value > self.__retrieve_value(other)

    def __le__(self, other: KWord) -> bool: 
        return self.value <= self.__retrieve_value(other)

    def __ge__(self, other: KWord) -> bool: 
        return self.value >= self.__retrieve_value(other)

    def __eq__(self, other: KWord) -> bool: 
        return self.value == self.__retrieve_value(other)

    def __ne__(self, other: KWord) -> bool: 
        return self.value != self.__retrieve_value(other)

    def __iadd__(self, other: KWord):
        self.value = self.__clamp(self._value + self.__retrieve_value(other))
        return self

    def __isub__(self, other: KWord):
        self.value = self.__clamp(self._value - self.__retrieve_value(other))
        return self

    def __imul__(self, other: KWord):
        self.value = self.__clamp(self._value * self.__retrieve_value(other))
        return self

    def __idiv__(self, other: KWord):
        self.value = self.__clamp(self._value / self.__retrieve_value(other))
        return self

    def __ifloordiv__(self, other: KWord):
        self.value = self.__clamp(self._value // self.__retrieve_value(other))
        return self

    def __imod__(self, other: KWord):
        self.value = self.__clamp(self._value % self.__retrieve_value(other))
        return self

    def __ipow__(self, other: KWord):
        self.value = self.__clamp(self._value ** self.__retrieve_value(other))
        return self

    def __irshift__(self, other: KWord):
        self.value = self.__clamp(self._value >> self.__retrieve_value(other))
        return self

    def __ilshift__(self, other: KWord):
        self.value = self.__clamp(self._value << self.__retrieve_value(other))
        return self

    def __iand__(self, other: KWord):
        self.value = self.__clamp(self._value & self.__retrieve_value(other))
        return self

    def __ior__(self, other: KWord):
        self.value = self.__clamp(self._value | self.__retrieve_value(other))
        return self

    def __ixor__(self, other: KWord):
        self.value = self.__clamp(self._value ^ self.__retrieve_value(other))
        return self

    def __neg__(self) -> KWord: 
        return KWord(-self.value & 0xFFFFFFFF, self.type)

    def __pos__(self) -> KWord: 
        return KWord(+self.value & 0xFFFFFFFF, self.type)

    def __invert__(self) -> KWord: 
        return KWord(~self.value & 0xFFFFFFFF, self.type)

    def __hash__(self):
        return hash(self.value + (self.type << 32))

    def __format__(self, fmt) -> str:
        return f"{self.value:{fmt}}"

    def is_absolute_addr(self) -> bool:
        return self.type == KWord.Types.ABSOLUTE

    def is_relative_addr(self) -> bool:
        return self.type == KWord.Types.RELATIVE

    def is_value(self) -> bool:
        return self.type == KWord.Types.VALUE

    def assert_value(self):
        if not self.is_value():
            raise InvalidOperationException(f"KWord {self.value} must be a value in this context")

    def assert_not_value(self):
        if self.is_value():
            raise InvalidOperationException(f"KWord {self.value} must not be a value in this context")

    def assert_relative(self):
        if not self.is_relative_addr():
            raise InvalidOperationException(f"KWord {self.value} must be a relative address in this context")

    def assert_not_relative(self):
        if self.is_relative_addr():
            raise InvalidOperationException(f"KWord {self.value} must not be a relative address in this context")

    def assert_absolute(self):
        if not self.is_absolute_addr():
            raise InvalidOperationException(f"KWord {self.value} must be a absolute address in this context")

    def assert_not_absolute(self):
        if self.is_absolute_addr():
            raise InvalidOperationException(f"KWord {self.value} must not be a absolute address in this context")

    def assert_not_ambiguous(self):
        if self.is_absolute_addr() and (self & 0x80000000) == 0:
            raise InvalidOperationException(f"{self.value} is ambiguous: absolute, top bit not set")
        if self.is_relative_addr() and (self & 0x80000000) != 0:
            raise InvalidOperationException(f"{self.value} is ambiguous: relative, top bit set")

    def __retrieve_value(self, other: KWord) -> int:
        if isinstance(other, KWord):
            return other.value
        elif isinstance(other, int):
            return self.__expand(self.__clamp(other))
        else:
            raise TypeError(f"Can't assign {type(other)} to class of type KWord using an operator")

    def __expand(self, value: int) -> int:
        if isinstance(value, KWord):
            value = value.value
        else:
            value = int(value)
        if self.signed:
            if value > 0x7FFFFFFF:
                value -= 0x100000000
            elif value < 0:
                value += 0x100000000
        return value

    @staticmethod
    def __clamp(value: int) -> int:
        if isinstance(value, KWord):
            value = value.value
        else:
            value = int(value)
        if value > 0x1FFFFFFFF or value < -0x1FFFFFFFF:
            raise ValueError(f"'{value}' is too extreme to clamp")
        elif value > 0xFFFFFFFF:
            value -= 0x100000000
        elif value < 0:
            value += 0x100000000
        return value