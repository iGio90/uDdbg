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
                'usage': 'memory [dump|read|patch|write] [...]',
                'help': 'Memory operations',
                'sub_commands': {
                    'dump': {
                        'help': 'Dump memory',
                        'function': {
                            "context": "memory_module",
                            "f": "dump"
                        }
                    },
                    'read': {
                        'usage': 'memory read [offset] [length] [optional format: h|i]',
                        'help': 'Read memory',
                        'function': {
                            "context": "memory_module",
                            "f": "read"
                        }
                    },
                    'patch': {
                        'help': 'Memory write with toggles'
                    },
                    'write': {
                        'help': 'Memory write'
                    },
                }
            }
        }

    def dump(self, func_name, *args):
        # todo
        pass

    def read(self, func_name, *args):
        if args:
            off = utils.input_to_offset(args[0])
            lent = utils.input_to_offset(args[1])
            format = 'h'
            if len(args) > 2:
                format = args[2]
            b = self.core_istance.get_emu_instance().mem_read(off, lent)
            if format == 'h':
                hexdump(b)
            elif format == 'i':
                cs = self.core_istance.get_cs_instance()
                for i in cs.disasm(bytes(b), off):
                    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            else:
                print('Format invalid. Please use a valid format:')
                print("\t" + 'h: hex')
                print("\t" + 'i: asm')

    def write(self, func_name, *args):
        # todo
        pass

    def patch(self, func_name, *args):
        # todo
        pass

    def init(self):
        pass

    def delete(self):
        pass
