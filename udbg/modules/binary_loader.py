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

import udbg.utils as utils
from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule


class BinaryLoader(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "binary_loader"
        self.command_map = {
            'lb': {
                'ref': "load",
            },
            "load": {
                'short': 'lb',
                'usage': 'load *file_path *offset',
                'function': {
                    "context": "binary_loader",
                    "f": "load"
                },
                'help': 'load binary and map it to specific offset'
            }
        }

    def load(self, func_name, *args):
        path = args[0]
        if os.path.isfile(path):
            p = open(path, 'rb').read()
            off = utils.u_eval(self.core_instance, args[1])
            binary_len = len(p)

            if off < 1024:
                off += 1024 - (off % 1024)

            if binary_len % 1024 is not 0:
                binary_len += 1024 - (binary_len % 1024)

            self.core_instance.get_emu_instance().mem_map(off, binary_len)
            self.core_instance.get_emu_instance().mem_write(off, p)
            self.core_instance.get_module('mappings_module').internal_add(off, binary_len, path)
            print('Mapped ' + str(binary_len) + ' at ' + hex(off))
        else:
            print("File not found")

    def init(self):
        pass

    def delete(self):
        pass
