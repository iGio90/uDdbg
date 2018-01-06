from abc import ABC, abstractmethod


class AbstractUnicornDbgModule(ABC):
    """
    skeleton class to inherit for every module.

    every module has to implement a command_map dictionary and a context_name

    structure example:

        self.context_name = "my_module_name"
        self.command_map = {
            "command_name":{
                "usage": "command_name usage", #optional
                "help": "command_name help description", #optional
                "short": "cn", #optional, reference to short command
                'sub_commands': { #optional
                    'sub_com1': {
                        ...
                    },
                "function": {  #optional when there are sub_commands - required when there are no sub_commands
                    "context": "my_module_name",
                    "f": "command_function"
                },

            },
            "ref_to_command_name":{
                "ref":"command_name" #optional
            }
        }

    every command method implementation has be like this:

        def command_function(self, func_name, *args):
            ...

    """

    def __init__(self, core_istance):
        """
        define required property context_name and command_map for every module
        """
        self.command_map = None
        self.context_name = None
        self.core_istance = core_istance

        @property
        def context_name(self):
            pass

        @property
        def command_map(self):
            pass

    """ required init and delete implementation for every module """

    @abstractmethod
    def init(self):
        pass

    @abstractmethod
    def delete(self):
        pass

    """ getter function for context_name and command_map """
    def get_context_name(self):
        return self.context_name

    def get_command_map(self):
        return self.command_map
