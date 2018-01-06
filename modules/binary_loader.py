import os

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
            try:
                off = input('Offset: ')
                if off.startswith('0x'):
                    off = int(off, 16)
                else:
                    off = int(off)
            except Exception as e:
                print('Invalid integer')
                return

            binary_len = len(p)

            if binary_len % 1024 is not 0:
                binary_len += 1024-(binary_len % 1024)

            print(hex(binary_len))

            self.core_istance.get_emu_instance().mem_map(off, binary_len)
            self.core_istance.get_emu_instance().mem_write(off, p)
            print('Mapped ' + str(binary_len) + ' at ' + hex(off))
        else:
            print("File not found")

    def init(self):
        pass

    def delete(self):
        pass
