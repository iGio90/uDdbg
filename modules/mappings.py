#############################################################################
#
#    Copyright (C) 2018
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

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Mappings(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.mappings = []
        self.context_name = "mappings_module"
        self.command_map = {
            'map': {
                'help': 'memory mappings',
                'usage': 'map [list|add|remove] [...]',
                'sub_commands': {
                    'l': {
                        'ref': "list",
                    },
                    'm': {
                        'ref': "map",
                    },
                    'u': {
                        'ref': "unmap",
                    },
                    'list': {
                        'short': 'l',
                        'usage': 'list',
                        'help': 'list mappings',
                        'function': {
                            "context": "mappings_module",
                            "f": "list"
                        }
                    },
                    'map': {
                        'usage': 'map *address *length [map name]',
                        'help': 'map *length at *address',
                        'function': {
                            "context": "mappings_module",
                            "f": "map"
                        }
                    },
                    'unmap': {
                        'usage': 'unmap [address] [length]',
                        'help': 'unmap *length at *address',
                        'function': {
                            "context": "mappings_module",
                            "f": "remove"
                        }
                    }
                }
            }
        }

    def list(self, func_name, *args):
        h = [utils.white_bold_underline('path'),
             utils.white_bold_underline('address'),
             utils.white_bold_underline('length')]
        print('')
        print(tabulate(self.mappings, h, tablefmt="simple"))
        print('')

    def map(self, func_name, *args):
        off = int(eval((args[0])))
        lent = int(eval((args[1])))

        p = None
        if len(args) > 2:
            p = str(args[2])

        if off < 1024:
            off += 1024 - (off % 1024)

        if lent % 1024 is not 0:
            lent += 1024 - (lent % 1024)

        self.core_instance.get_emu_instance().mem_map(off, lent)
        self.internal_add(off, lent, p)
        print('mapped ' + str(lent) + ' at ' + hex(off))

    def unmap(self, func_name, *args):
        off = int(eval((args[0])))
        lent = int(eval((args[1])))

        if off < 1024:
            off += 1024 - (off % 1024)

        if lent % 1024 is not 0:
            lent += 1024 - (lent % 1024)

        self.core_instance.get_emu_instance().mem_unmap(off, lent)
        for i in range(0, len(self.mappings)):
            if self.mappings[i][1] == off:
                map_lent = self.mappings[i][2]
                if map_lent == lent:
                    self.mappings.pop(i)
        print('unmapped ' + str(lent) + ' at ' + hex(off))

    def internal_add(self, address, length, path=None):
        self.mappings.append([path, hex(address), length])

    def init(self):
        pass

    def delete(self):
        pass
