from modules.unicorndbgmodule import AbstractUnicornDbgModule
from termcolor import colored
import sys
from tabulate import tabulate

MENU_APIX = '[' + colored('*', 'cyan', attrs=['bold', 'dark']) + ']'


class CoreModule(AbstractUnicornDbgModule):
    """
    core functions module. Here we implement all the core functions of the UnicornDbg
    """

    def __init__(self, core_instance):
        """
        create a context_name and command_map as requested from the UnicornDbgModule
        :param core_instance:
        """
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "core_module"
        self.command_map = {
            'q': {
                'ref': "quit",
            },
            'exit': {
                'ref': "quit",
            },
            's': {
                'ref': "show",
            },
            'c': {
                'ref': "start",
            },
            'b': {
                'ref': "breakpoint",
            },
            'bkp': {
                'ref': "breakpoint",
            },
            'break': {
                'ref': "breakpoint",
            },
            'quit': {
                'short': 'q',
                'function': {
                    "context": "core_module",
                    "f": "quit"
                },
                'help': 'Quit command'
            },
            'help': {
                'function': {
                    "context": "core_module",
                    "f": "help"
                },
                'help': 'Show command',
                'usage': 'help [command]'
            },
            'breakpoint': {
                'short': 'b,bkp,break',
                'function': {
                    "context": "core_module",
                    "f": "breakpoint"
                },
                'help': 'Break the emulation at specific offset',
                'usage': 'breakpoint [address]'
            },
            'show': {
                'short': 's',
                'usage': 'show [mappings|patches]',
                'help': 'Show list of mappings and patches',
                'function': {
                    "context": "core_module",
                    "f": "show"
                },
                'sub_commands': {
                    'mappings': {
                        'help': 'Show list of mappings',
                        'sub_commands': {
                            'sub1': {
                                'help': 'TEST SUB'
                            }
                        },
                    },
                    'patches': {
                        'help': 'Show list of patches'
                    },
                }
            },
            'start': {
                'short': 'c',
                'usage': 'start',
                'help': 'Start emulation',
                'function': {
                    "context": "core_module",
                    "f": "show"
                }
            },
            'modules': {
                'function': {
                    "context": "core_module",
                    "f": "modules"
                },
                'help': 'Loaded modules list'
            },
        }

    def breakpoint(self, *args):
        # todo
        pass

    def show(self, *args):
        pass

    def modules(self, func_name, *args):
        """
        print a list of all loaded modules (included all core modules)

        :param func_name:
        :param args:
        :return:
        """

        print("Loaded modules: \n")
        for module in self.core_istance.context_map:
            if module is not "self":
                print("\t" + MENU_APIX + " " + colored(module, 'white', attrs=['underline', 'bold']))

    def help(self, func_name, *args):
        """
        print the help and command usage of the requested command (and subcommand too)

        help command_to_get_help [subcommand_to_get_help1 subcommand_to_get_help2]

        :param func_name:
        :param args:
        :return:
        """

        # we need at least 1 command to get the help
        if args:
            try:
                # h will keep the command dictionary iteration
                # c will keep the deep of the subcommand iteration
                h = None
                c = 0
                prev_h = None

                # iterate for every command and subcommand in args
                for arg in args:
                    c += 1
                    # keep a reference (usefull for errors) of command\sub_command name
                    main_command = arg

                    # if we already fetched the first main command
                    if h:
                        # if we have a sub_command save the reference so we can iterate into it
                        if "sub_commands" in h:
                            if len(h["sub_commands"]) is not 0:
                                # save the parent command
                                prev_h = h
                                h = h["sub_commands"][arg]
                            else:
                                raise Exception
                        else:
                            raise Exception
                    # if is the first fetch of the main command just search it on the commands_map dict
                    # and save the reference. We will start the command root from here
                    else:
                        # if the requested command is a "ref" to another command, just keep the right reference
                        if "ref" in self.core_istance.commands_map[arg]:
                            h = self.core_istance.commands_map[self.core_istance.commands_map[arg]["ref"]]
                        else:
                            h = self.core_istance.commands_map[arg]
                        # keep a reference to parent command
                        prev_h = h

                if c > 0:
                    # if the sub_command is a reference to another associated sub_command
                    if "ref" in h:
                        h = prev_h['sub_commands'][h['ref']]

                    # print help and usage passing h, the command object reference
                    print(h["help"])
                    self.print_usage(h)
                    # if there are sub_commands print a list of them
                    if "sub_commands" in h:
                        print("\nSub commands list:")
                        self.print_command_list(h["sub_commands"])

            except Exception as e:
                print("search Err: " + str(e))
                print("No help for command '" + main_command + "'" + ' found')
                self.print_usage(func_name)

        # if we have no args (so no commands) just print the commands list
        else:
            print("\nCommands list:")
            self.print_command_list(self.core_istance.commands_map)

    def quit(self, *args):
        """
        exit function, here goes all the handles in order to clean quit the system

        :param args:
        :return:
        """

        # for every loaded module call the delete method for safe close
        for module in self.core_istance.context_map:
            if module is not "self":
                self.core_istance.context_map[module].delete()
        sys.exit(0)

    def print_usage(self, command, only_get=False):
        """
        utils function to check (if exist) and print the command usage

        :param command: command of which to print usage description
        :param only_get: if True he will not print the usage but only returns it
        :return:
        """

        if isinstance(command, dict):
            com = command
        else:
            com = self.core_istance.commands_map[command]

        try:
            if "usage" in com:
                if only_get is False:
                    print("Usage: " + com["usage"])
                return com["usage"]
            else:
                return None
        except Exception as e:
            return None

    def print_command_list(self, com_obj):
        """
        print the command list of the com_obj reference passed (could be root or even a sub_command reference)
        :param com_obj: command object reference
        :return:
        """
        try:
            com_array = []
            for com in com_obj:
                # if a short reference is present print (short)
                # if the command is a ref, ignore it
                if "ref" not in com_obj[com]:
                    com_array.append(com)


            # sort the list of commands and print it
            com_array.sort()
            command_table_arr = []
            for com in com_array:
                com_t = []
                com_t.append(com)
                have_shorts = "short" in com_obj[com]
                if have_shorts:
                    com_t.append(com_obj[com]["short"])
                else:
                    com_t.append('')

                com_t.append(self.print_usage(com_obj[com], only_get=True))
                command_table_arr.append(com_t)

            print(tabulate(command_table_arr, ['command', 'short', 'usage'], tablefmt="rst"))

        except Exception as e:
            print("command_list err:"+e)

                #print("\t" + colored(com + " (" + com_obj[com]["short"] + ")", 'white', attrs=['underline', 'bold']))
            #else:
                #print("\t" + colored(com, 'white', attrs=['underline', 'bold']))

            #if "help" in com_obj[com]:
                #print("\t" + com_obj[com]["help"])
                #print("\n")

    def init(self):
        pass

    def delete(self):
        pass
