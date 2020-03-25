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
from unicorn import *
from unicorn.x86_const import *

import udbg.utils as utils
from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule
from udbg.arch import *


class Registers(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "registers_module"
        self.command_map = {
            'r': {
                'ref': "registers",
            },
            'reg': {
                'ref': "registers",
            },
            'regs': {
                'ref': "registers",
            },
            'register': {
                'ref': "registers",
            },
            'registers': {
                'short': 'r,reg,regs',
                'usage': 'registers [read|write] [...]',
                'help': 'print registers summary if no args given',
                'function': {
                    "context": "registers_module",
                    "f": "registers"
                },
                'sub_commands': {
                    'w': {
                        'ref': "write",
                    },
                    'r': {
                        'ref': "read",
                    },
                    'write': {
                        'short': 'w',
                        'usage': 'registers write *register (i.e r0) *value',
                        'help': 'write value into registers',
                        'function': {
                            "context": "registers_module",
                            "f": "write"
                        }
                    },
                    'read': {
                        'short': 'r',
                        'usage': 'registers read *register (i.e r0)',
                        'help': 'read specific register',
                        'function': {
                            "context": "registers_module",
                            "f": "read"
                        }
                    }
                }
            }
        }

    def registers(self, func_name, *args):
        print(utils.titlify('registers'))
        arch = self.core_instance.unicorndbg_instance.arch
        mode = self.core_instance.unicorndbg_instance.mode
        regtable = getRegStringTable(getArchString(arch, mode))
        r = []
        for regcode in regtable:
            r.append(self.reg(regtable[regcode], regcode))
        h = [utils.white_bold_underline('register'),
             utils.white_bold_underline('hex'),
             utils.white_bold_underline('decimal')]
        print(tabulate(r, h, tablefmt="simple"))

    @property
    def emu_instance(self):
        return self.core_instance.get_emu_instance()

    def reg(self, name: str, uc_const: int):
        """
        Create an entry for a new reg, reading the contents from unicorn.
        """
        uc = self.emu_instance
        val = uc.reg_read(uc_const)
        return [utils.green_bold(name), hex(val), val]

    def write(self, func_name, *args):
        arch = self.core_instance.unicorndbg_instance.get_arch()
        try:
            register = getattr(utils.get_arch_consts(arch), utils.get_reg_tag(arch) + str(args[0]).upper())
        except Exception as e:
            raise Exception('register not found')

        value = utils.u_eval(self.core_instance, args[1])
        self.core_instance.get_emu_instance().reg_write(register, value)
        print(hex(value) + ' written into ' + str(args[0]).upper())

    def read(self, func_name, *args):
        reg = str(args[0]).upper()
        value = self.read_register(reg)
        if value is None:
            raise Exception('register not found')

        r = [[utils.green_bold(reg), hex(value), str(value)]]
        h = [utils.white_bold_underline('register'),
             utils.white_bold_underline('hex'),
             utils.white_bold_underline('decimal')]
        print('')
        print(tabulate(r, h, tablefmt="simple"))
        print('')

    def read_register(self, reg):
        arch = self.core_instance.unicorndbg_instance.get_arch()
        try:
            register = getattr(utils.get_arch_consts(arch), utils.get_reg_tag(arch) + reg)
        except Exception as e:
            return None
        return self.core_instance.get_emu_instance().reg_read(register)

    def init(self):
        pass

    def delete(self):
        pass
