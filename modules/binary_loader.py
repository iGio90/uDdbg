import os

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class BinaryLoader(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "binary_loader"
        self.command_map = {
            "load": {
                'function': {
                    "context": "binary_loader",
                    "f": "load"
                },
                'help': 'Load binary and map it to specific offset'
            }
        }

    def load(self, func_name, *args):
        p = input("Binary path: ")
        if os.path.isfile(p):
            p = open(p, 'rb').read()
            off = utils.input_to_offset(input('Offset: '))

            binary_len = len(p)

            if off < 1024:
                off += 1024 - (off % 1024)

            if binary_len % 1024 is not 0:
                binary_len += 1024 - (binary_len % 1024)

            self.core_instance.get_emu_instance().mem_map(off, binary_len)
            self.core_instance.get_emu_instance().mem_write(off, p)
            print('Mapped ' + str(binary_len) + ' at ' + hex(off))
        else:
            print("File not found")

    def init(self):
        pass

    def delete(self):
        pass
