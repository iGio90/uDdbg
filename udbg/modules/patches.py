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

from tabulate import tabulate
import udbg.utils as utils
from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule


class Patches(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.patches = []
        self.context_name = "patches_module"
        self.command_map = {
            'patch': {
                'help': 'Patches',
                'usage': 'patch [list|add|remove|toggle] [...]',
                'sub_commands': {
                    'l': {
                        'ref': "list",
                    },
                    'a': {
                        'ref': "add",
                    },
                    'r': {
                        'ref': "remove",
                    },
                    'rm': {
                        'ref': "remove",
                    },
                    't': {
                        'ref': "toggle",
                    },
                    'list': {
                        'short': 'l',
                        'usage': 'list',
                        'help': 'list mappings',
                        'function': {
                            "context": "patches_module",
                            "f": "list"
                        }
                    },
                    'add': {
                        'usage': 'add *address *hex_payload',
                        'help': 'write *hex_payload into *address',
                        'function': {
                            "context": "patches_module",
                            "f": "add"
                        }
                    },
                    'remove': {
                        'usage': 'remove *address',
                        'help': 'remove active patch at *address',
                        'function': {
                            "context": "patches_module",
                            "f": "remove"
                        }
                    },
                    'toggle': {
                        'usage': 'toggle *address *status (0: off / 1: on)',
                        'help': 'toggle patch at *address',
                        'function': {
                            "context": "patches_module",
                            "f": "toggle"
                        }
                    }
                }
            }
        }

    def list(self, func_name, *args):
        h = [utils.green_bold('address'),
             utils.green_bold('length'),
             utils.green_bold('status')]
        print(tabulate(self.patches, h, tablefmt="simple"))

    def add(self, func_name, *args):
        off = utils.u_eval(self.core_instance, args[0])
        pp = bytes.fromhex(args[1])
        pp_len = len(pp)

        for i in range(0, len(self.patches)):
            p = self.patches[i]
            if p[0] == off:
                print(hex(off) + ' already patched')
                return

        memory_module = self.core_instance.get_module('memory_module')
        orig_pp = memory_module.internal_read(off, pp_len)
        memory_module.internal_write(off, pp)
        self.patches.append([off, pp_len, orig_pp, pp, 1])
        print('patch created and written to ' + hex(off))

    def remove(self, func_name, *args):
        off = utils.u_eval(self.core_instance, args[0])
        for i in range(0, len(self.patches)):
            p = self.patches[i]
            if p[0] == off:
                self.patches.pop(i)
                print('patch at ' + hex(off) + ' removed.')
                return
        print('no patch found at ' + hex(off))

    def toggle(self, func_name, *args):
        off = utils.u_eval(self.core_instance, args[0])
        for i in range(0, len(self.patches)):
            p = self.patches[i]
            if p[0] == off:
                tog = args[1]
                status = p[4]

                memory_module = self.core_instance.get_module('memory_module')

                if status == 0 and tog == 1:
                    p[4] = tog
                    memory_module.internal_write[off, p[3]]
                    print('patch at ' + hex(off) + ' enabled')
                    return
                elif status == 1 and tog == 0:
                    p[4] = tog
                    memory_module.internal_write[off, p[2]]
                    print('patch at ' + hex(off) + ' disabled')
                    return
            print('Nothing to do at ' + hex(off))
            return
        print('no patch found at ' + hex(off))

    def init(self):
        pass

    def delete(self):
        pass
