import capstone
import inquirer

from capstone import *
from modules.core_module import CoreModule
from modules import binary_loader, memory, module_test, registers, mappings
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import prompt
from termcolor import colored
from unicorn import *
import traceback, sys

MENU_APPENDIX = '$>'
MENU_APIX = '[' + colored('*', 'cyan', attrs=['bold', 'dark']) + ']'


class UnicornDbgFunctions(object):
    """
    The core class of the UnicornDbg. With this we manage all the functions, functionality and execution flow
    """

    def __init__(self, unicorndbg_instance):
        # in context_map we keep a list of loaded modules associated with their instances.
        # We will use them in exec_command
        self.context_map = {
            "self": self,
        }

        # in commands_map we keep a list of loaded commands from all the modules
        self.commands_map = {}
        self.unicorndbg_instance = unicorndbg_instance

        # create a core_module instance (with all core commands and functionality) and load them
        # pass an instance of self in order to allow cores methods to get access to context_map and commands_map
        core_module_instance = CoreModule(self)
        self.add_module(core_module_instance)

        mappings_module = mappings.Mappings(self)
        self.add_module(mappings_module)

        binary_loader_module = binary_loader.BinaryLoader(self)
        self.add_module(binary_loader_module)

        memory_module = memory.Memory(self)
        self.add_module(memory_module)

        registers_module = registers.Registers(self)
        self.add_module(registers_module)

    def exec_command(self, command, args):
        """
        the core method of commands exec, it tries to fetch the requested command,
        bind to the right context and call the associated function

        TODO:
        :param command: requested command
        :param args: arguments array
        :return:
        """
        mirror_args = args
        try:
            main_command = command
            if main_command == '':
                return

            if command in self.commands_map:

                # if we found the command but has the "ref" property,
                # so we need to reference to another object. Ex. short command q --references--> quit
                if 'ref' in self.commands_map[command]:
                    com = self.commands_map[self.commands_map[command]['ref']]
                else:
                    com = self.commands_map[command]

                # if we have no arguments no sub_command exist, else save the first argument
                last_function = False
                if len(args) > 0:
                    possible_subcommand = args[0]
                else:
                    possible_subcommand = None

                # now iterate while we have a valid subcommand,
                # when we don't find a valid subcommand exit and the new command will be the subcommand
                while last_function is False:
                    # save the sub_command parent
                    prev_command = com
                    if 'sub_commands' in com and possible_subcommand:
                        if possible_subcommand in com['sub_commands']:
                            com = com['sub_commands'][possible_subcommand]
                            # pop the found subcommand so we can iterate on the remanings arguments
                            args.pop(0)
                            command = possible_subcommand
                            # if there are arguments left
                            if len(args) > 0:
                                possible_subcommand = args[0]
                            else:
                                last_function = True

                        else:
                            last_function = True
                    else:
                        last_function = True

                # if the sub_command is a reference to another associated sub_command
                if 'ref' in com:
                    com = prev_command['sub_commands'][com['ref']]

                # if we have a function field just fetch the context and the function name,
                # bind them and call the function passing the arguments
                if 'function' in com:
                    context = self.context_map[com["function"]["context"]]
                    funct = com["function"]["f"]
                    call_method = getattr(context, funct)
                    # we pass the command name (could be usefull for the called function)
                    # and possible arguments to the function
                    call_method(command, *args)
                else:
                    # if we have no method implementation of the command
                    # print the help of the command
                    # passing all the arguments list to help function
                    print([main_command]+mirror_args)
                    self.exec_command('help', [main_command]+mirror_args)

            else:
                print("Command '"+command+"' not found")
        except Exception as e:
            print("exec Err: "+str(e)+"\n")
            self.exec_command('help', [main_command])


        #print("Debug args: %s"%args)

    def get_emu_instance(self):
        """ expose emu instance """
        return self.unicorndbg_instance.get_emu_instance()

    def get_cs_instance(self):
        """ expose capstone instance """
        return self.unicorndbg_instance.get_cs_instance()

    def get_module(self, module_key):
        return self.context_map[module_key]

    def add_module(self, module):
        """
        add a module to the core.

        :param module: class instance of the module
        :return:
        """
        try:
            # get the context_name (or module name) and the command_map from the module.
            # These 2 functions are ensured by class inheritance of UnicornDbgModule
            context_name = module.get_context_name()
            command_map = module.get_command_map()

            # check if is all valid and if we have not already loaded it
            if context_name not in self.commands_map and context_name not in self.context_map and len(command_map) \
                    is not 0 and len(context_name) is not 0:

                # add the module to the context_map and push new commands on the commands_map
                # check if command already exist in the command map, if yes trigger error for the module load
                for com in command_map:
                    if com in self.commands_map:
                        raise Exception('Command "'+com+'" already exist')
                    else:
                        self.commands_map[com] = command_map[com]

                self.context_map[context_name] = module

                print(MENU_APIX+" Module "+colored(context_name, 'white', attrs=['underline', 'bold'])+" loaded")
                # call the module init function
                module.init()
                return True
            else:
                raise Exception("module already loaded")
        except Exception as e:
            print("Error in adding '" + context_name + "' module. Err: "+str(e))
            return False


class UnicornDbg(object):
    @staticmethod
    def boldify(x):
        return colored(x, attrs=['bold'])

    def __init__(self, module_arr=None):
        self.arch = None
        self.mode = None
        self.emu_instance = None
        self.cs = None
        self.current_address = 0x0

        self.history = InMemoryHistory()

        # create UnicornDbgFunctions instance
        self.functions_instance = UnicornDbgFunctions(self)

        # if we pass an array with modules, just load them
        # remember: we can load modules both on the UnicornDbg creation and after with the
        #           add_module method
        if module_arr:
            for module in module_arr:
                self.add_module(module)

    def add_module(self, module):
        """
        add modules to UnicornDbg core
        just an interface to call add_module in UnicornDbgFunctions

        """
        self.functions_instance.add_module(module)

    def start(self, arch, mode):
        self.arch = getattr(unicorn_const, arch)
        self.mode = getattr(unicorn_const, mode)
        self.emu_instance = Uc(self.arch, self.mode)

        main_apix = colored(MENU_APPENDIX + " ", 'red', attrs=['bold', 'dark'])
        while True:
            print(main_apix, end='', flush=False)
            text = prompt('', history=self.history, auto_suggest=AutoSuggestFromHistory())
            # send command to the parser
            self.parse_command(text)

    def resume_emulation(self, address=0x0):
        if address > 0x0:
            self.current_address = address
        self.emu_instance.emu_start(self.current_address)

    def get_emu_instance(self):
        """ expose emu instance """
        return self.emu_instance

    def get_cs_instance(self):
        """ expose capstone instance """
        if self.cs is None:
            print('\nSetup capstone engine.')
            a = getattr(capstone, prompt_cs_arch())
            m = getattr(capstone, prompt_cs_mode())
            self.cs = Cs(a, m)
        return self.cs

    def get_arch(self):
        return self.arch

    def get_current_address(self):
        return self.current_address

    def parse_command(self, text):
        """
        parse command section, here we will make first filters and checks
        TODO: i think we can filter here args (like -w) from sub commands
        """
        try:
            command_arr = text.split(' ')

            command = command_arr[0]
            args = command_arr[1:]
            self.functions_instance.exec_command(command, args)

        except AttributeError as e:
            print('error in parsing command')


def prompt_arch():
    items = [k for k, v in unicorn_const.__dict__.items() if not k.startswith("__") and k.startswith("UC_ARCH")]
    return prompt_list(items, 'arch', 'Select arch')


def prompt_mode():
    items = [k for k, v in unicorn_const.__dict__.items() if not k.startswith("__") and k.startswith("UC_MODE")]
    return prompt_list(items, 'mode', 'Select mode')


def prompt_cs_arch():
    items = [k for k, v in capstone.__dict__.items() if not k.startswith("__") and k.startswith("CS_ARCH")]
    return prompt_list(items, 'arch', 'Select arch')


def prompt_cs_mode():
    items = [k for k, v in capstone.__dict__.items() if not k.startswith("__") and k.startswith("CS_MODE")]
    return prompt_list(items, 'mode', 'Select mode')


def prompt_list(items, key, hint):
    base_path = [
        inquirer.List(key,
                      message=hint,
                      choices=items)]
    r = inquirer.prompt(base_path)
    return r[key]


if __name__ == "__main__":
    udbg = UnicornDbg()
    t = module_test.MyModule(udbg)

    udbg.add_module(t)

    arch = prompt_arch()
    mode = prompt_mode()

    udbg.start(arch, mode)

