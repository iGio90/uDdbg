import os

from hexdump import hexdump

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Registers(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "registers_module"
        self.command_map = {
            'r': {
                'ref': "registers",
            },
            'registers': {
                'short': 'r',
                'usage': 'registers [dump|read|write] [...]',
                'help': 'Memory operations',
                'function': {
                    "context": "registers_module",
                    "f": "registers"
                },
                'sub_commands': {
                    'write': {
                        'short': 'w',
                        'usage': 'registers write [register] [value]',
                        'help': 'Write value into registers',
                        'function': {
                            "context": "memory_module",
                            "f": "dump"
                        }
                    },
                    'read': {
                        'usage': 'registers write [register] [value]',
                        'help': 'Dump memory',
                        'function': {
                            "context": "memory_module",
                            "f": "dump"
                        }
                    }
                }
            }
        }

    def registers(self, func_name, *args):
        pass

    def init(self):
        pass

    def delete(self):
        pass
