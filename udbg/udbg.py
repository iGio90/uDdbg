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

from typing import List, Tuple

from prompt_toolkit.formatted_text import FormattedText

from udbg.modules.core_module import CoreModule
from udbg.modules import binary_loader, memory, module_test, registers, mappings, patches, asm, configs, executors, \
    find, stepover
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import prompt
from termcolor import colored
from unicorn import *
from unicorn import unicorn_const

import sys
import udbg.utils as utils
import copy
from udbg.arch import *

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

        find_module = find.Find(self)
        self.add_module(find_module)

        stepover_module = stepover.StepOver(self)
        self.add_module(stepover_module)

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
                    if 'args' in com['function']:
                        args_check, args_error = utils.check_args(com['function']['args'], args)
                        if args_check is False:
                            raise Exception(args_error)

                    context = self.context_map[com["function"]["context"]]
                    funct = com["function"]["f"]
                    call_method = getattr(context, funct)
                    # we pass the command name (could be useful for the called function)
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
                print(utils.titlify('uc error'))
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
            l = len(commands_arr)
            if l > 0:
                for com in commands_arr:
                    self.parse_command(com)
                print('executed ' + utils.green_bold(str(l) + ' commands') + '.')
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
        self.is_thumb = False
        self.cs_arch = None
        self.cs_mode = None
        self.emu_instance = None  # type: Uc
        self.cs = None
        self.entry_point = None
        self.exit_point = None
        self.current_address = 0x0
        self.last_mem_invalid_size = 0x0
        self.entry_context = {}
        self.trace_instructions = 0x0
        self.skip_bp_count = 0x0

        self.history = InMemoryHistory()

        # create UnicornDbgFunctions instance
        self.functions_instance = UnicornDbgFunctions(self)

        # if we pass an array with modules, just load them
        # remember: we can load modules both on the UnicornDbg creation and after with the
        #           add_module method
        if module_arr:
            for module in module_arr:
                self.add_module(module(self.functions_instance))

        # hold some modules
        self.core_module = self.get_module('core_module')
        self.register_module = self.get_module('registers_module')
        self.asm_module = self.get_module('asm_module')
        # last breakpoint
        self.last_bp = 0x0
        self.soft_bp = False
        self.has_soft_bp = False
        self.breakpoint_count = 0x0
        # mem access
        self.mem_access_result = None
        self.hook_mem_access = False
        # hold last command
        self.last_command = None

    def dbg_hook_code(self, uc, address, size, user_data):
        """
        Unicorn instructions hook
        """
        try:
            self.current_address = address

            hit_soft_bp = False
            should_print_instruction = self.trace_instructions > 0

            if self.soft_bp:
                self.hook_mem_access = True
                self.soft_bp = False
                hit_soft_bp = True

            if address != self.last_bp and \
                    (address in self.core_module.get_breakpoints_list() or
                     self.has_soft_bp):
                if self.skip_bp_count > 0:
                    self.skip_bp_count -= 1
                else:
                    self.breakpoint_count += 1
                    should_print_instruction = False
                    uc.emu_stop()

                    self.last_bp = address

                    print(utils.titlify('breakpoint'))
                    print('[' + utils.white_bold(str(self.breakpoint_count)) +
                          ']' + ' hit ' + utils.red_bold('breakpoint') +
                          ' at: ' + utils.green_bold(hex(address)))
                    self._print_context(uc, address)
            elif address == self.last_bp:
                self.last_bp = 0
            self.has_soft_bp = hit_soft_bp
            if self.current_address + size == self.exit_point:
                should_print_instruction = False
                self._print_context(uc, address)
                print(utils.white_bold("emulation") + " finished with " + utils.green_bold("success"))
            if should_print_instruction:
                self.asm_module.internal_disassemble(uc.mem_read(address, size), address)
        except KeyboardInterrupt as ex:
            # If stuck in an endless loop, we can exit here :). TODO: does that mean ctrl+c never works for targets?
            print(utils.titlify('paused'))
            self._print_context(uc, address)
            uc.emu_stop()

    def dbg_hook_mem_access(self, uc, access, address, size, value, user_data):
        if self.hook_mem_access:
            self.hook_mem_access = False
            # store to ensure a print after disasm
            self.mem_access_result = [address, value]

    def dbg_hook_mem_invalid(self, uc: Uc, access, address, size, value, userdata):
        """
        Unicorn mem invalid hook
        """
        if size < 2:
            size = self.last_mem_invalid_size
        self.last_mem_invalid_size = size
        self.register_module.registers('mem_invalid')
        print(utils.titlify('disasm'))
        start = max(0, self.pc - 0x16)
        self.asm_module.internal_disassemble(uc.mem_read(start, 0x32), start, address)

    def _print_context(self, uc, pc):
        self.register_module.registers('mem_invalid')
        print(utils.titlify('disasm'))
        self.asm_module.internal_disassemble(uc.mem_read(pc - 0x16, 0x32), pc - 0x16, pc)
        if self.mem_access_result is not None:
            val = utils.red_bold("\t0x%x" % self.mem_access_result[1])
            ad = utils.green_bold("\t> 0x%x" % self.mem_access_result[0])
            print(utils.titlify("memory access"))
            print(utils.white_bold("WRITE") + val + ad)
            self.hook_mem_access = None
            self.mem_access_result = None

    def add_module(self, module):
        """
        add modules to UnicornDbg core
        just an interface to call add_module in UnicornDbgFunctions
        """
        self.functions_instance.add_module(module)

    def initialize(self, emu_instance: Uc = None, arch=None, mode=None, hide_binary_loader=False,
                   entry_point=None, exit_point=None, mappings: List[Tuple[str, int, int]] = None) -> Uc:
        """
        Initializes the emulator with all needed hooks. 
        Will return the unicorn emu_instance ready to go. 
        This method can be called from external scripts to to embed udbg.
        To kick off emulation, run start().
        :param entry_point: Entrypoint
        :param exit_opint: Exitpoint (where to stop emulation)
        :param emu_instance: Optional Unicorn instance to initialize this debugger with
        :param hide_binary_loader: if True, binary loader submenus will be hidden (good if embedding udbg in a target uc script)
        :param arch: unicorn arch int costant
        :param mode: unicorn mode int costant
        :param mappings: list of mappings as tuple: [(name, offset, size),...]
        :return: Fully initialzied Uc instance.
        """

        binary_loader_module = binary_loader.BinaryLoader(self)
        self.add_module(binary_loader_module)

        if emu_instance:
            self.emu_instance = emu_instance

        self.current_address = self.entry_point = entry_point
        self.exit_point = exit_point

        # if no arch or mode are sets in param, prompt for them
        if not arch:
            if emu_instance:
                arch = emu_instance._arch
            else:
                arch = utils.prompt_arch()
        if not mode:
            if emu_instance:
                mode = emu_instance._mode
            else:
                mode = utils.prompt_mode()

        if isinstance(arch, str):
            self.arch = getattr(unicorn_const, arch)
        else:
            self.arch = arch

        if isinstance(mode, str):
            self.mode = getattr(unicorn_const, mode)
        else:
            self.mode = mode

        if not self.emu_instance:
            self.emu_instance = Uc(self.arch, self.mode)

        if self.mode == UC_MODE_THUMB:
            self.is_thumb = True

        if mappings:
            [self.get_module('mappings_module').internal_add(*mapping[1:], path=mapping[0]) for mapping in mappings]

        # add hooks
        self.emu_instance.hook_add(UC_HOOK_CODE, self.dbg_hook_code)
        self.emu_instance.hook_add(UC_HOOK_MEM_WRITE, self.dbg_hook_mem_access)
        self.emu_instance.hook_add(UC_HOOK_MEM_INVALID, self.dbg_hook_mem_invalid)

        return self.emu_instance

    @property
    def pc(self):
        reg = getPCCode(getArchString(self.arch, self.mode))
        return self.emu_instance.reg_read(reg)

    def start(self):
        """
        main start function, here we handle the command get loop and unicorn istance creation
       :return:
        """

        if not self.emu_instance:
            self.initialize()

        utils.clear_terminal()
        print(utils.get_banner())
        print('\n\n\t' + utils.white_bold('Contribute ') + 'https://github.com/iGio90/uDdbg\n')
        print('\t' + 'Type ' + utils.white_bold_underline('help') + ' to begin.\n')

        print()
        while True:
            text = prompt(FormattedText([('ansired bold', MENU_APPENDIX + ' ')]), history=self.history, auto_suggest=AutoSuggestFromHistory())

            # only grant the use of empty command to replicate the last command while in cli. No executors
            if len(text) == 0 and self.last_command is not None:
                self.functions_instance.parse_command(self.last_command)
                continue

            self.last_command = text

            # send command to the parser
            self.functions_instance.parse_command(text)

    def resume_emulation(self, address=None, skip_bp=0):
        if address is not None:
            self.current_address = address

        self.skip_bp_count = skip_bp

        if self.exit_point is not None:
            print(utils.white_bold("emulation") + " started at " + utils.green_bold(hex(self.current_address)))

            if len(self.entry_context) == 0:
                # store the initial memory context for the restart
                self.entry_context = {
                    'memory': {},
                    'regs': {}
                }
                map_list = self.get_module('mappings_module').get_mappings()
                for map in map_list:
                    map_address = int(map[1], 16)
                    map_len = map[2]
                    self.entry_context['memory'][map_address] = bytes(self.emu_instance.mem_read(map_address, map_len))
                # registers
                const = utils.get_arch_consts(self.arch)
                regs = [k for k, v in const.__dict__.items() if
                        not k.startswith("__") and "_REG_" in k and not "INVALID" in k]
                for r in regs:
                    try:
                        self.entry_context['regs'][r] = self.emu_instance.reg_read(getattr(const, r))
                    except Exception as ex:
                        pass
                        # print("Ignoring reg: {} ({})".format(r, ex)) -> Ignored UC_X86_REG_MSR

            start_addr = self.current_address
            if self.is_thumb:
                start_addr = start_addr | 1
            self.emu_instance.emu_start(start_addr, self.exit_point)
        else:
            print('please use \'set exit_point *offset\' to define an exit point')

    def restore(self):
        self.current_address = self.entry_point
        for addr in self.entry_context['memory']:
            m = self.entry_context['memory'][addr]
            self.emu_instance.mem_write(addr, m)
        print('restored ' + str(len(self.entry_context['memory'])) + ' memory regions.')
        const = utils.get_arch_consts(self.arch)
        for r in self.entry_context['regs']:
            self.emu_instance.reg_write(getattr(const, r), self.entry_context['regs'][r])
        print('restored ' + str(len(self.entry_context['regs'])) + ' registers.')
        print('emulator at ' + utils.green_bold(hex(self.current_address)))

    def stop_emulation(self):
        self.emu_instance.emu_stop()

    def get_emu_instance(self):
        """ expose emu instance """
        return self.emu_instance

    def get_cs_instance(self):
        """ expose capstone instance """
        if self.cs is None:
            if self.arch is not None or self.mode is not None:
                archstring = getArchString(self.arch, self.mode)
                self.cs_arch, self.cs_mode = getCapstoneSetup(archstring)

            self.functions_instance.get_module('configs_module').push_config('cs_mode', self.cs_mode)

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
        return self.exit_point

    def get_module(self, module_key):
        return self.functions_instance.get_module(module_key)

    def batch_execute(self, commands):
        self.functions_instance.batch_execute(commands)

    def exec_command(self, command):
        self.functions_instance.exec_command(command)


def main():
    udbg = UnicornDbg()
    t = module_test.MyModule(udbg)
    udbg.add_module(t)

    udbg.start()


if __name__ == "__main__":
    main()
