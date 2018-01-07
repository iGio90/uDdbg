from tabulate import tabulate
from unicorn import *

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Patches(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.patches = []
        self.context_name = "patches_module"
        self.command_map = {
            'patch': {
                'short': 'p',
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
                        'usage': 'add [address] [hex payload]',
                        'help': 'write *payload into *address',
                        'function': {
                            "context": "patches_module",
                            "f": "add"
                        }
                    },
                    'remove': {
                        'usage': 'remove [address]',
                        'help': 'remove active patch at *address',
                        'function': {
                            "context": "patches_module",
                            "f": "remove"
                        }
                    },
                    'toggle': {
                        'usage': 'toggle [address]',
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
        off = utils.input_to_offset(args[0])
        pp = bytes.fromhex(args[1])
        pp_len = len(pp)

        for i in range(0, len(self.patches)):
            p = self.patches[i]
            if p[0] == off:
                self.patches.pop(i)
                print(hex(off) + ' already patched')
                return

        memory_module = self.core_instance.get_module('memory_module')
        orig_pp = memory_module.internal_read(off, pp_len)
        memory_module.internal_write(off, pp)
        self.patches.append([off, pp_len, orig_pp, pp, 1])
        print('patch created and written to ' + hex(off))

    def remove(self, func_name, *args):
        off = utils.input_to_offset(args[0])
        for i in range(0, len(self.patches)):
            p = self.patches[i]
            if p[0] == off:
                self.patches.pop(i)
                print('patch at ' + hex(off) + ' removed.')
                return
        print('no patch found at ' + hex(off))

    def toggle(self, address, length, path=None):
        pass

    def init(self):
        pass

    def delete(self):
        pass
