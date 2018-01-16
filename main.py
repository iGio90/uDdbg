import capstone
import os

import time
from capstone import *

from modules.core_module import CoreModule
from modules import binary_loader, memory, module_test, registers, mappings, patches, asm, configs, executors
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import prompt
from termcolor import colored
from unicorn import *
import sys
import utils
import copy

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

        # load modules
        try:
            self.load_core_modules()
        except Exception as e:
            print(e)
            self.quit()

    def load_core_modules(self):
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

        patches_module = patches.Patches(self)
        self.add_module(patches_module)

        asm_module = asm.ASM(self)
        self.add_module(asm_module)

        configs_module = configs.Configs(self)
        self.add_module(configs_module)

        executors_module = executors.Executors(self)
        self.add_module(executors_module)

    def exec_command(self, command, args):
        """
        the core method of commands exec, it tries to fetch the requested command,
        bind to the right context and call the associated function

        TODO:
        :param command: requested command
        :param args: arguments array
        :return:
        """

        # save the found command and sub_command array
        complete_command_array = [command]
        try:
            if command == '':
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
                    possible_sub_command = args[0]
                else:
                    possible_sub_command = None

                # now iterate while we have a valid sub_command,
                # when we don't find a valid sub_command exit and the new command will be the sub_command
                # save the sub_command parent
                prev_command = com
                while last_function is False:
                    # if the sub command is a ref, catch the right command
                    if 'ref' in com:
                        com = prev_command['sub_commands'][com['ref']]
                    if 'sub_commands' in com and possible_sub_command:
                        if possible_sub_command in com['sub_commands']:
                            prev_command = com
                            com = com['sub_commands'][possible_sub_command]
                            # pop the found sub_command so we can iterate on the remanings arguments
                            complete_command_array.append(args.pop(0))
                            command = possible_sub_command
                            # if there are arguments left
                            if len(args) > 0:
                                # take the first args (the next sub_command)
                                possible_sub_command = args[0]
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
                    # passing all the arguments list to help function (including the command) in a unique array
                    self.exec_command('help', complete_command_array)

            else:
                print("command '" + command + "' not found")
        except Exception as e:
            if isinstance(e, UcError):
                print(str(e))
            else:
                print(utils.error_format('exec_command', str(e)))
                self.exec_command('help', complete_command_array)

    def get_dbg_instance(self):
        """ expose dbg instance """
        return self.unicorndbg_instance

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
        context_name = module.get_context_name()
        command_map = module.get_command_map()

        try:
            # get the context_name (or module name) and the command_map from the module.
            # These 2 functions are ensured by class inheritance of UnicornDbgModule

            # check if is all valid and if we have not already loaded it
            if context_name not in self.commands_map and context_name not in self.context_map and len(command_map) \
                    is not 0 and len(context_name) is not 0:

                # add the module to the context_map and push new commands on the commands_map
                # check if command already exist in the command map, if yes trigger error for the module load
                for com in command_map:
                    if com in self.commands_map:
                        raise Exception('command "' + com + '" already exist')

                self.commands_map.update(copy.deepcopy(command_map))
                self.context_map[context_name] = module

                print(MENU_APIX + " Module " + colored(context_name, 'white', attrs=['underline', 'bold']) + " loaded")
                # call the module init function
                module.init()
            else:
                raise Exception("module already loaded")
        except Exception as e:
            raise Exception("Error in adding '" + context_name + "' module.\nErr: " + str(e))

    def batch_execute(self, commands_arr):
        """
        batch execute a list of commands
        :param commands_arr: array with commands
        :return:
        """
        try:
            if len(commands_arr) > 0:
                print(MENU_APIX + colored(" Batch execution of " + str(len(commands_arr)) + " commands", 'white',
                                          attrs=['underline', 'bold']))
                for com in commands_arr:
                    self.parse_command(com)
            else:
                raise Exception
        except Exception as e:
            print(MENU_APIX + " " + colored("FAILED", 'red', attrs=['underline', 'bold']) + " " + colored(
                "batch execution of " + str(len(commands_arr)) + " commands", 'white', attrs=['underline', 'bold']))

    def parse_command(self, text):
        """
        parse command section, here we will make first filters and checks
        TODO: i think we can filter here args (like -w) from sub commands
        """
        try:
            command_arr = text.split(' ')

            command = command_arr[0]
            args = command_arr[1:]
            self.exec_command(command, args)

        except AttributeError as e:
            print('error in parsing command')

    def quit(self):
        """
        exit function, here goes all the handles in order to clean quit the system

        :param args:
        :return:
        """

        # for every loaded module call the delete method for safe close
        for module in self.context_map:
            if module is not "self":
                self.context_map[module].delete()
        sys.exit(0)


class UnicornDbg(object):
    @staticmethod
    def boldify(x):
        return colored(x, attrs=['bold'])

    def __init__(self, module_arr=None):
        self.arch = None
        self.mode = None
        self.cs_arch = None
        self.cs_mode = None
        self.emu_instance = None
        self.cs = None
        self.entry_point = 0x0
        self.exit_point = 0x0
        self.current_address = 0x0
        self.last_mem_invalid_size = 0x0

        self.history = InMemoryHistory()

        # create UnicornDbgFunctions instance
        self.functions_instance = UnicornDbgFunctions(self)

        # if we pass an array with modules, just load them
        # remember: we can load modules both on the UnicornDbg creation and after with the
        #           add_module method
        if module_arr:
            for module in module_arr:
                self.add_module(module)

    def dbg_hook_code(self, uc, address, size, user_data):
        """
        Unicorn instructions hook
        """
        self.current_address = address
        if address in self.functions_instance.get_module('core_module').get_breakpoints_list():
            print('hit breakpoint at: ' + hex(address))
            uc.stop_emulation()

    def dbg_hook_mem_invalid(self, uc, access, address, size, value, userdata):
        """
        Unicorn mem invalid hook
        """

        if size < 2:
            size = self.last_mem_invalid_size
        self.last_mem_invalid_size = size

        pc = uc.reg_read(arm_const.UC_ARM_REG_PC)
        self.get_module('registers_module').registers('mem_invalid')
        self.get_module('asm_module').internal_disassemble(
            uc.mem_read(pc, size), pc)

    def add_module(self, module):
        """
        add modules to UnicornDbg core
        just an interface to call add_module in UnicornDbgFunctions
        """
        self.functions_instance.add_module(module)

    def start(self, arch=None, mode=None):
        """
        main start function, here we handle the command get loop and unicorn istance creation
        :param arch: unicorn arch int costant
        :param mode: unicorn mode int costant
        :return:
        """

        # if no arch or mode are sets in param, prompt for them
        if not arch:
            arch = utils.prompt_arch()
        if not mode:
            mode = utils.prompt_mode()

        self.arch = getattr(unicorn_const, arch)
        self.mode = getattr(unicorn_const, mode)

        self.emu_instance = Uc(self.arch, self.mode)

        # add hooks
        self.emu_instance.hook_add(UC_HOOK_CODE, self.dbg_hook_code)
        self.emu_instance.hook_add(UC_HOOK_MEM_INVALID, self.dbg_hook_mem_invalid)

        utils.clear_terminal()
        print(utils.get_banner())
        print('\n\n\t' + utils.white_bold('Contribute ') + 'https://github.com/iGio90/uDdbg\n')
        print('\t' + 'Type ' + utils.white_bold_underline('help') + ' to begin.\n')

        main_apix = colored(MENU_APPENDIX + " ", 'red', attrs=['bold', 'dark'])
        while True:
            print(main_apix, end='', flush=True)
            text = prompt('', history=self.history, auto_suggest=AutoSuggestFromHistory())
            # send command to the parser
            self.functions_instance.parse_command(text)

    def resume_emulation(self, address=0x0):
        if address > 0x0:
            self.current_address = address

        if self.exit_point > 0x0:
            self.emu_instance.emu_start(self.current_address, self.exit_point)
        else:
            print('please use \'set exit_point *offset\' to define an exit point')

    def stop_emulation(self):
        self.emu_instance.emu_stop()

    def get_emu_instance(self):
        """ expose emu instance """
        return self.emu_instance

    def get_cs_instance(self):
        """ expose capstone instance """
        if self.cs is None:
            print('\nSetup capstone engine.')
            if self.cs_arch is None:
                arch = utils.prompt_cs_arch()
                self.cs_arch = getattr(capstone, arch)
                self.functions_instance.get_module('configs_module').push_config('cs_arch', arch)

            mode = utils.prompt_cs_mode()
            self.cs_mode = getattr(capstone, mode)

            self.functions_instance.get_module('configs_module').push_config('cs_mode', mode)

            self.cs = Cs(self.cs_arch, self.cs_mode)
        return self.cs

    def set_cs_arch(self, arch):
        self.cs_arch = arch
        if self.cs_mode is not None:
            self.cs = Cs(self.cs_arch, self.cs_mode)

    def set_cs_mode(self, mode):
        self.cs_mode = mode
        if self.cs_arch is not None:
            self.cs = Cs(self.cs_arch, self.cs_mode)

    def set_entry_point(self, entry_point):
        self.entry_point = entry_point

    def set_exit_point(self, exit_point):
        self.exit_point = exit_point

    def get_arch(self):
        return self.arch

    def get_mode(self):
        return self.mode

    def get_cs_arch(self):
        return self.cs_arch

    def get_cs_mode(self):
        return self.cs_mode

    def get_current_address(self):
        return self.current_address

    def get_entry_point(self):
        return self.entry_point

    def get_exit_point(self):
        return self.entry_point

    def get_module(self, module_key):
        return self.functions_instance.get_module(module_key)

    def batch_execute(self, commands):
        self.functions_instance.batch_execute(commands)


if __name__ == "__main__":
    udbg = UnicornDbg()
    t = module_test.MyModule(udbg)
    udbg.add_module(t)

    udbg.start()
