import capstone
import keystone
from tabulate import tabulate

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Configs(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)

        # init config maps
        self.configs_map = {
            'cs_arch': '',
            'cs_mode': '',
            'ks_arch': '',
            'ks_mode': ''
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
                'usage': 'configs',
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
            r.append([utils.green_bold(key), self.configs_map[key]])
        h = [utils.white_bold_underline('config'),
             utils.white_bold_underline('value')]
        print('')
        print(tabulate(r, h, tablefmt="simple"))
        print('')

    def set(self, func_name, *args):
        key = args[0]
        value = args[1]
        if key not in self.configs_map:
            print('config not found')
        else:
            if key == 'cs_arch':
                try:
                    arch = getattr(capstone, 'CS_ARCH_' + str(args[1]).upper())
                except Exception as e:
                    raise Exception('arch not found')
                self.configs_map[key] = 'CS_ARCH_' + str(args[1]).upper()
                self.core_instance.set_cs_arch(arch)
            elif key == 'cs_mode':
                try:
                    mode = getattr(capstone, 'CS_MODE_' + str(args[1]).upper())
                except Exception as e:
                    raise Exception('mode not found')
                self.configs_map[key] = 'CS_MODE_' + str(args[1]).upper()
                self.core_instance.set_cs_mode(mode)
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

            else:
                self.configs_map[key] = value

    def push_config(self, key, value):
        self.configs_map[key] = value
        self.configs_map = sorted(self.configs_map)

    def init(self):
        pass

    def delete(self):
        pass
