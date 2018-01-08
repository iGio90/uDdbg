from tabulate import tabulate
from unicorn import *

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Executors(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "executors_module"
        self.command_map = {
            'fexec': {
                'help': 'batch execute uddbg commands from a text file (1 command per line)',
                'usage': 'fexec *file_path',
                'function': {
                    "context": "executors_module",
                    "f": "fexec"
                }
            }
        }

    def fexec(self, func_name, *args):
        pass

    def init(self):
        pass

    def delete(self):
        pass
