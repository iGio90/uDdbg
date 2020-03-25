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


class Mappings(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.mappings = []
        self.context_name = "mappings_module"
        self.command_map = {
            'map': {
                'help': 'memory mappings',
                'function': {
                    "context": "mappings_module",
                    "f": "list"
                }
            }
        }

    def list(self, func_name, *args):
        print(utils.titlify('mappings'))
        h = [utils.white_bold_underline('path'),
             utils.white_bold_underline('address'),
             utils.white_bold_underline('length')]
        print('')
        print(tabulate(self.mappings, h, tablefmt="simple"))
        print('')

    def internal_add(self, address, length, path=None):
        self.mappings.append([path, hex(address), length])

    def get_mappings(self):
        return self.mappings

    def init(self):
        pass

    def delete(self):
        pass
