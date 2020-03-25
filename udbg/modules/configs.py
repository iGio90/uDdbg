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

import capstone
import keystone
from tabulate import tabulate

import udbg.utils as utils
from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule


class Configs(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)

        # init config maps
        self.configs_map = {
            'cs_arch': '',
            'cs_mode': '',
            'entry_point': 0x0,
            'exit_point': 0x0,
            'ks_arch': '',
            'ks_mode': '',
            'print_instructions': 0
        }

        self.context_name = "configs_module"
        self.command_map = {
            'conf': {
                'ref': "configs",
            },
            'config': {
                'ref': "configs",
            },
            'configs': {
                'help': 'print available configurations',
                'function': {
                    "context": "configs_module",
                    "f": "configs"
                }
            },
            'set': {
                'help': 'set configuration',
                'usage': 'set *config_name *value',
                'function': {
                    "context": "configs_module",
                    "f": "set"
                }
            }
        }

    def configs(self, func_name, *args):
        r = []

        for key in self.configs_map:
            val = self.configs_map[key]
            if isinstance(val, int):
                val = hex(val)
            r.append([utils.green_bold(key), val])
        h = [utils.white_bold_underline('config'),
             utils.white_bold_underline('value')]
        print('')
        print(tabulate(r, h, tablefmt="simple"))
        print('')

    def set(self, func_name, *args):
        key = args[0]
        value = eval((args[1]))
        if key not in self.configs_map:
            print('config not found')
        else:
            if key == 'cs_arch':
                try:
                    arch = getattr(capstone, 'CS_ARCH_' + str(args[1]).upper())
                except Exception as e:
                    raise Exception('arch not found')
                self.configs_map[key] = 'CS_ARCH_' + str(args[1]).upper()
                self.core_instance.get_dbg_instance().set_cs_arch(arch)
            elif key == 'cs_mode':
                try:
                    mode = getattr(capstone, 'CS_MODE_' + str(args[1]).upper())
                except Exception as e:
                    raise Exception('mode not found')
                self.configs_map[key] = 'CS_MODE_' + str(args[1]).upper()
                self.core_instance.get_dbg_instance().set_cs_mode(mode)
            elif key == 'entry_point':
                value = int(value)
                self.core_instance.get_dbg_instance().set_entry_point(value)
                self.configs_map[key] = value
            elif key == 'exit_point':
                value = int(value)
                self.core_instance.get_dbg_instance().set_exit_point(value)
                self.configs_map[key] = value
            elif key == 'ks_arch':
                try:
                    arch = getattr(keystone, 'KS_ARCH_' + str(args[1]).upper())
                except Exception as e:
                    raise Exception('arch not found')
                self.configs_map[key] = 'KS_ARCH_' + str(args[1]).upper()
                self.core_instance.get_module('asm_module').set_ks_arch(arch)
            elif key == 'ks_mode':
                try:
                    mode = getattr(keystone, 'KS_MODE_' + str(args[1]).upper())
                except Exception as e:
                    raise Exception('mode not found')
                self.configs_map[key] = 'KS_MODE_' + str(args[1]).upper()
                self.core_instance.get_module('asm_module').set_ks_mode(mode)
            elif key == 'print_instructions':
                value = int(value)
                if value > 1:
                    value = 1
                self.configs_map[key] = value
                self.core_instance.get_dbg_instance().trace_instructions = value
            else:
                self.configs_map[key] = value

    def push_config(self, key, value):
        self.configs_map[key] = str(value)

    def init(self):
        pass

    def delete(self):
        pass
