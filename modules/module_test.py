from modules.unicorndbgmodule import AbstractUnicornDbgModule


class MyModule(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "my_module"
        self.command_map = {
            "module_test": {
                'function': {
                    "context": "my_module",
                    "f": "module_test"
                },
                'help': 'My_module test function'
            }
        }

    def module_test(self, func_name, *args):
        print("This is a test from my_module test function")

    def init(self):
        pass

    def delete(self):
        pass
