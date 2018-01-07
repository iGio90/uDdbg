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
            'map': {
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
                        'help': 'List mappings',
                        'function': {
                            "context": "patches_module",
                            "f": "list"
                        }
                    },
                    'add': {
                        'usage': 'add [address] [hex payload]',
                        'help': 'Write *payload into *address',
                        'function': {
                            "context": "patches_module",
                            "f": "add"
                        }
                    },
                    'remove': {
                        'usage': 'remove [address]',
                        'help': 'Remove active patch at *address',
                        'function': {
                            "context": "patches_module",
                            "f": "remove"
                        }
                    },
                    'toggle': {
                        'usage': 'toggle [address]',
                        'help': 'Toggle patch at *address',
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
        pass

    def remove(self, address, length, path=None):
        pass

    def toggle(self, address, length, path=None):
        pass

    def init(self):
        pass

    def delete(self):
        pass
