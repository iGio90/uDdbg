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

from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule
import udbg.utils as utils


class MyModule(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "my_module"
        self.command_map = {
            "module_test": {
                'function': {
                    "context": "my_module",
                    "f": "module_test",
                    'args': 'int hexsum intsum'
                },
                'help': 'HELP My_module test function',
                'sub_commands': {
                    'sub1': {
                        'help': 'SUB1 HELP',
                        'function': {
                            'context': 'my_module',
                            'f': 'sub1'
                        }
                    },
                    's1': {
                        'ref': 'sub1'
                    }
                }
            }
        }

    def module_test(self, func_name, *args):
        print("This is a test from my_module test function")
        # print(utils.check_args("int int hex @str", args))

    def sub1(self, func_name, *args):
        print("CALL TO SUB1")

    def init(self):
        pass

    def delete(self):
        pass
