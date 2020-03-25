#############################################################################
#
#    Copyright (C) 2020
#    Giovanni -iGio90- Rocca, Vincenzo -rEDSAMK- Greco
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>
#
#############################################################################
#
# Unicorn DOPE Debugger
#
# Runtime bridge for unicorn emulator providing additional api to play with
# Enjoy, have fun and contribute
#
# Github: https://github.com/iGio90/uDdbg
# Twitter: https://twitter.com/iGio90
#
#############################################################################
import os
from hexdump import hexdump

import udbg.utils as utils
from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule


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
                'usage': 'memory [dump|fwrite|map|read|write|unmap] [...]',
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
                    'fw': {
                        'ref': "fwrite",
                    },
                    'm': {
                        'ref': "map",
                    },
                    'u': {
                        'ref': "unmap",
                    },
                    'um': {
                        'ref': "unmap",
                    },
                    'umap': {
                        'ref': "unmap",
                    },
                    'map': {
                        'short': 'm',
                        'usage': 'map *address *length [map name]',
                        'help': 'map *length at *address',
                        'function': {
                            "context": "memory_module",
                            "f": "map"
                        }
                    },
                    'unmap': {
                        'short': 'u,um',
                        'usage': 'unmap [address] [length]',
                        'help': 'unmap *length at *address',
                        'function': {
                            "context": "memory_module",
                            "f": "unmap"
                        }
                    },
                    'dump': {
                        'short': 'd',
                        'usage': 'memory dump *offset *length *file_path]',
                        'help': 'dump memory',
                        'function': {
                            "context": "memory_module",
                            "f": "dump"
                        }
                    },
                    'read': {
                        'short': 'r',
                        'usage': 'memory read *offset *length [format: h|i]',
                        'help': 'read memory',
                        'function': {
                            "context": "memory_module",
                            "f": "read"
                        }
                    },
                    'write': {
                        'short': 'w',
                        'usage': 'memory write *offset *hex_payload',
                        'help': 'memory write',
                        'function': {
                            "context": "memory_module",
                            "f": "write"
                        }
                    },
                    'fwrite': {
                        'short': 'fw',
                        'usage': 'memory fwrite *offset *file_path',
                        'help': 'write binary into offset',
                        'function': {
                            "context": "memory_module",
                            "f": "fwrite"
                        }
                    }
                }
            }
        }

    def map(self, func_name, *args):
        off = utils.u_eval(self.core_instance, args[0])
        lent = utils.u_eval(self.core_instance, args[1])

        p = None
        if len(args) > 2:
            p = str(args[2])

        if off < 1024:
            off += 1024 - (off % 1024)

        if lent % 1024 is not 0:
            lent += 1024 - (lent % 1024)

        self.core_instance.get_emu_instance().mem_map(off, lent)
        mappings = self.core_instance.get_module('mappings_module')
        mappings.internal_add(off, lent, p)
        print('mapped ' + str(lent) + ' at ' + hex(off))

    def unmap(self, func_name, *args):
        off = utils.u_eval(self.core_instance, args[0])
        lent = utils.u_eval(self.core_instance, args[1])

        if off < 1024:
            off += 1024 - (off % 1024)

        if lent % 1024 is not 0:
            lent += 1024 - (lent % 1024)

        self.core_instance.get_emu_instance().mem_unmap(off, lent)
        mappings = self.core_instance.get_module('mappings_module').get_mappings()
        for i in range(0, len(mappings)):
            if int(mappings[i][1], 0) == off:
                map_lent = mappings[i][2]
                if map_lent == lent:
                    mappings.pop(i)
        print('unmapped ' + str(lent) + ' at ' + hex(off))

    def dump(self, func_name, *args):
        off = utils.u_eval(self.core_instance, args[0])
        lent = utils.u_eval(self.core_instance, args[1])
        file_name = args[3]
        b = self.core_instance.get_emu_instance().mem_read(off, lent)
        with open(file_name, 'wb') as f:
            f.write(b)
        print(str(lent) + ' bytes written to ' + file_name + '.')

    def read(self, func_name, *args):
        off = utils.u_eval(self.core_instance, args[0])
        lent = utils.u_eval(self.core_instance, args[1])
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
        off = utils.u_eval(self.core_instance, args[0])
        pp = bytes.fromhex(args[1])
        self.internal_write(off, pp)
        print(str(len(pp)) + ' bytes written to ' + hex(off))

    def fwrite(self, func_name, *args):
        off = utils.u_eval(self.core_instance, args[0])
        path = args[1]
        if not os.path.isfile(path):
            print('file not found or not accessible.')
            return
        with open(path, "rb") as bb:
            self.internal_write(off, bb.read())
            print(path + ' bytes written to ' + hex(off))

    def internal_write(self, off, payload):
        self.core_instance.get_emu_instance().mem_write(off, payload)

    def internal_read(self, off, l):
        return self.core_instance.get_emu_instance().mem_read(off, l)

    def init(self):
        pass

    def delete(self):
        pass
