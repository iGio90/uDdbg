import os

from hexdump import hexdump

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Memory(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "memory_module"
        self.command_map = {
            'm': {
                'ref': "memory",
            },
            'memory': {
                'short': 'm',
                'usage': 'memory [dump|read|write] [...]',
                'help': 'memory operations',
                'sub_commands': {
                    'd': {
                        'ref': "dump",
                    },
                    'r': {
                        'ref': "read",
                    },
                    'w': {
                        'ref': "write",
                    },
                    'dump': {
                        'short': 'd',
                        'usage': 'memory dump [offset] [length] [file path]',
                        'help': 'dump memory',
                        'function': {
                            "context": "memory_module",
                            "f": "dump"
                        }
                    },
                    'read': {
                        'short': 'r',
                        'usage': 'memory read [offset] [length] [optional format: h|i]',
                        'help': 'read memory',
                        'function': {
                            "context": "memory_module",
                            "f": "read"
                        }
                    },
                    'write': {
                        'short': 'w',
                        'usage': 'memory write [offset] [hex payload]',
                        'help': 'memory write',
                        'function': {
                            "context": "memory_module",
                            "f": "write"
                        }
                    },
                }
            }
        }

    def dump(self, func_name, *args):
        off = utils.input_to_offset(args[0])
        lent = utils.input_to_offset(args[1])
        file_name = args[3]
        b = self.core_instance.get_emu_instance().mem_read(off, lent)
        with open(file_name, 'wb') as f:
            f.write(b)
        print(str(lent) + ' written to ' + file_name + '.')

    def read(self, func_name, *args):
        off = utils.input_to_offset(args[0])
        lent = utils.input_to_offset(args[1])
        format = 'h'
        if len(args) > 2:
            format = args[2]
        b = self.core_instance.get_emu_instance().mem_read(off, lent)
        if format == 'h':
            hexdump(b)
        elif format == 'i':
            cs = self.core_instance.get_cs_instance()
            for i in cs.disasm(bytes(b), off):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        else:
            print('format invalid. Please use a valid format:')
            print("\t" + 'h: hex')
            print("\t" + 'i: asm')

    def write(self, func_name, *args):
        off = utils.input_to_offset(args[0])
        pp = bytes.fromhex(args[1])
        self.internal_write(off, pp)
        print(str(len(pp)) + ' written to ' + hex(off))

    def internal_write(self, off, payload):
        self.core_instance.get_emu_instance().mem_write(off, payload)

    def internal_read(self, off, l):
        return self.core_instance.get_emu_instance().mem_read(off, l)

    def init(self):
        pass

    def delete(self):
        pass
