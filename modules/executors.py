import os

from tabulate import tabulate

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Executors(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.executors_map = {}
        self.executors_id_map = {}

        self.context_name = "executors_module"
        self.command_map = {
            'e': {
                'ref': "executors",
            },
            'ex': {
                'ref': "executors",
            },
            'exe': {
                'ref': "executors",
            },
            'exec': {
                'ref': "executors",
            },
            'executor': {
                'ref': "executors",
            },
            'executors': {
                'short': 'r,reg,regs',
                'help': 'manage executors',
                'usage': 'exec [delete|load|new|run|save]',
                'function': {
                    "context": "executors_module",
                    "f": "exec"
                },
                'sub_commands': {
                    'd': {
                        'ref': "delete",
                    },
                    'del': {
                        'ref': "delete",
                    },
                    'l': {
                        'ref': "load",
                    },
                    'ld': {
                        'ref': "load",
                    },
                    'delete': {
                        'short': 'd,del',
                        'usage': 'exec delete *executors_id',
                        'help': 'delete an executor',
                        'function': {
                            "context": "executors_module",
                            "f": "del_exec"
                        }
                    },
                    'load': {
                        'short': 'l,ld',
                        'usage': 'exec load *file_path',
                        'help': 'load an executor from file (1 command per line)',
                        'function': {
                            "context": "executors_module",
                            "f": "load_exec"
                        }
                    }
                }
            }
        }

    def exec(self, func_name, *args):
        print(utils.titlify('help'))
        print(utils.green_bold('usage: ') + self.command_map['executors']['usage'])
        r = []
        for key, value in self.executors_map.items():
            id = value['id']
            cmd_count = str(len(value['cmd_list']))
            r.append([str(id), key, cmd_count])
        h = [utils.white_bold_underline('id'),
             utils.white_bold_underline('name'),
             utils.white_bold_underline('commands')]
        print(utils.titlify('executors'))
        print(tabulate(r, h, tablefmt="simple"))

    def load_exec(self, func_name, *args):
        f = args[0]
        if not os.path.isfile(f):
            print('file not found or not accessible')
            return
        fp = open(f, 'r').read()
        cmd_arr = fp.split("\n")
        key = f
        id = len(self.executors_map)
        executor = {
            'id': id,
            'cmd_list': cmd_arr
        }
        self.executors_map[key] = executor
        self.executors_id_map[id] = key
        self.core_instance.batch_execute(cmd_arr)

    def del_exec(self, func_name, *args):
        try:
            id = int(args[0])
            if id not in self.executors_id_map:
                print('executor not found')
            else:
                v = self.executors_id_map[id]
                self.executors_id_map.pop(id)
                self.executors_map.pop(v)
                print(utils.green_bold(str(id)) + ": removed")
        except Exception as e:
            print(utils.green_bold('usage: ') + 'exec delete *executor_id')

    def init(self):
        pass

    def delete(self):
        pass
