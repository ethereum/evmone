import gdb

EVMC_BYTES_TARGET_TYPES = [
    "evmc::address",
    "const evmc::address",
    "evmc_address",
    "const evmc_address",
    "evmc::bytes32",
    "const evmc::bytes32",
    "evmc_bytes32",
    "const evmc_bytes32",
    "evmc_uint256be",
    "const evmc_uint256be",
    "evmc::uint256be",
    "const evmc::uint256be",
]


class EvmcBytesPrinter:
    def __init__(self, val):
        self.val = val

    def to_string(self):
        start = self.val['bytes']
        bytes_int = [int(start[i]) for i in range(start.type.range()[1] + 1)]
        return "0x" + (''.join(f'{byte:02x}' for byte in bytes_int))


INTX_UINT_TARGET_TYPES = [
    "intx::uint<256>",
    "const intx::uint<256>",
]

class IntxUintPrinter:
    def __init__(self, val):
        self.val = val

    def to_string(self):
        words = self.val['words_']
        words_int = [int(words[i]) for i in range(4)]
        v = words_int[0] + (words_int[1] << 64) + (words_int[2] << 128) + (words_int[3] << 192)
        return str(v)

# In CLion these are automatically overwritten by std::* pretty printers.
# Reload this script manually (`source -v ../../gdb_pretty_printers.py`) to activate them again.
STRING_TARGET_TYPES = [
    "std::__cxx11::basic_string<unsigned char, evmc::byte_traits<unsigned char>, std::allocator<unsigned char> >",
    "const std::__cxx11::basic_string<unsigned char, evmc::byte_traits<unsigned char>, std::allocator<unsigned char> >",
]


class StdBasicStringUint8Printer:
    def __init__(self, val):
        self.val = val

    def to_string(self):
        start = self.val['_M_dataplus']['_M_p']
        length = self.val['_M_string_length']
        content = [int(start[i]) for i in range(length)]
        return '{size = %d, data = {%s}}' % (length, ', '.join(hex(byte) for byte in content))


STRING_VIEW_TARGET_TYPES = [
    "std::basic_string_view<unsigned char, evmc::byte_traits<unsigned char> >",
    "const std::basic_string_view<unsigned char, evmc::byte_traits<unsigned char> >",
]


class StdBasicStringViewUint8Printer:
    def __init__(self, val):
        self.val = val

    def to_string(self):
        start = self.val['_M_str']
        length = self.val['_M_len']
        content = [int(start[i]) for i in range(length)]
        return '{size = %d, data = {%s}}' % (length, ', '.join(hex(byte) for byte in content))

def register_printers(obj):
    if obj == None:
        obj = gdb
    obj.pretty_printers.insert(0, lookup_function)


def lookup_function(val):
    type_str = str(val.type.strip_typedefs())
    # print("lookup " + type_str)  # uncomment to see exact type requested

    if type_str in EVMC_BYTES_TARGET_TYPES:
        return EvmcBytesPrinter(val)

    if type_str in INTX_UINT_TARGET_TYPES:
        return IntxUintPrinter(val)

    if type_str in STRING_TARGET_TYPES:
        return StdBasicStringUint8Printer(val)

    if type_str in STRING_VIEW_TARGET_TYPES:
        return StdBasicStringViewUint8Printer(val)

    return None


register_printers(gdb.current_objfile())
