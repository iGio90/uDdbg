from modules.unicorndbgmodule import AbstractUnicornDbgModule
import utils


class MyModule(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "my_module"
        self.command_map = {
            "module_test": {
                'function': {
                    "context": "my_module",
                    "f": "module_test",
                    'args': 'int hexsum intsum'
                },
                'help': 'HELP My_module test function',
                'sub_commands': {
                    'sub1': {
                        'help': 'SUB1 HELP',
                        'function': {
                            'context': 'my_module',
                            'f': 'sub1'
                        }
                    },
                    's1': {
                        'ref': 'sub1'
                    }
                }
            }
        }

    def module_test(self, func_name, *args):
        print("This is a test from my_module test function")
        # print(utils.check_args("int int hex @str", args))

    def sub1(self, func_name, *args):
        print("CALL TO SUB1")

    def init(self):
        pass

    def delete(self):
        pass
