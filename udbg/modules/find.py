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
import re

from tabulate import tabulate

import udbg.utils as utils
from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule


class Find(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)

        self.context_name = "module_find"
        self.command_map = {
            'f': {
                'ref': "find",
            },
            "find": {
                'short': 'f',
                'usage': 'find [*map|*offset] *hex',
                'function': {
                    "context": "module_find",
                    "f": "find"
                },
                'help': 'find hexa in memory map region'
            }
        }

    def find(self, func_name, *args):
        where = utils.u_eval(self.core_instance, args[0])

        what = bytes.fromhex(args[1])
        match = re.compile(what)

        result = []
        map_start = 0
        start = 0
        size = 0
        mappings = self.core_instance.get_module('mappings_module').get_mappings()

        if isinstance(where, str):
            for map in mappings:
                if map[0] == where:
                    start = int(map[1], 16)
                    map_start = start
                    size = map[2]
        else:
            for map in mappings:
                if int(map[1], 16) <= where < (int(map[1], 16) + map[2]):
                    map_start = int(map[1], 16)
                    start = where
                    size = map[2]

        b = self.core_instance.get_emu_instance().mem_read(start, size - (map_start - start))
        for match_obj in match.finditer(b):
            offset = match_obj.start() + map_start
            result.append([hex(offset)])

        print(utils.titlify('find'))
        if len(result) == 0:
            print('Nothing found.')
        else:
            h = [
                 utils.white_bold_underline('offset')
            ]
            print('')
            print(tabulate(result, h, tablefmt="simple"))
            print('')

    def init(self):
        pass

    def delete(self):
        pass
