#############################################################################
#
#    Copyright (C) 2020
#    Giovanni -iGio90- Rocca, Vincenzo -rEDSAMK- Greco
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>
#
#############################################################################
#
# Unicorn DOPE Debugger
#
# Runtime bridge for unicorn emulator providing additional api to play with
# Enjoy, have fun and contribute
#
# Github: https://github.com/iGio90/uDdbg
# Twitter: https://twitter.com/iGio90
#
#############################################################################

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

    def __init__(self, core_instance):
        """
        define required property context_name and command_map for every module
        """
        self.command_map = None
        self.context_name = None
        self.core_instance = core_instance

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
