import os

from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Executors(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "executors_module"
        self.command_map = {
            'fexec': {
                'help': 'execute uddbg commands from a text file (1 command per line)',
                'usage': 'fexec *file_path',
                'function': {
                    "context": "executors_module",
                    "f": "fexec"
                }
            },
            'bexec': {
                'help': 'execute uddbg commands at specific breakpoint hit',
                'usage': 'bexec *breakpoint_id',
                'function': {
                    "context": "executors_module",
                    "f": "bexec"
                }
            }
        }

    def fexec(self, func_name, *args):
        f = args[0]
        if not os.path.isfile(f):
            raise Exception('file not found or not accessible')
        f = open(f, 'r').read()
        cmd_arr = f.split("\n")
        self.core_instance.batch_execute(cmd_arr)

    def bexec(self, func_name, *args):
        pass

    def init(self):
        pass

    def delete(self):
        pass
