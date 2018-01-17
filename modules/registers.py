from tabulate import tabulate
from unicorn import *

import utils
from modules.unicorndbgmodule import AbstractUnicornDbgModule


class Registers(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.context_name = "registers_module"
        self.command_map = {
            'r': {
                'ref': "registers",
            },
            'reg': {
                'ref': "registers",
            },
            'regs': {
                'ref': "registers",
            },
            'register': {
                'ref': "registers",
            },
            'registers': {
                'short': 'r,reg,regs',
                'usage': 'registers [read|write] [...]',
                'help': 'print registers summary if no args given',
                'function': {
                    "context": "registers_module",
                    "f": "registers"
                },
                'sub_commands': {
                    'w': {
                        'ref': "write",
                    },
                    'r': {
                        'ref': "read",
                    },
                    'write': {
                        'short': 'w',
                        'usage': 'registers write *register (i.e r0) *value',
                        'help': 'write value into registers',
                        'function': {
                            "context": "registers_module",
                            "f": "write"
                        }
                    },
                    'read': {
                        'short': 'r',
                        'usage': 'registers read *register (i.e r0)',
                        'help': 'read specific register',
                        'function': {
                            "context": "registers_module",
                            "f": "read"
                        }
                    }
                }
            }
        }

    def registers(self, func_name, *args):
        print(utils.titlify('registers'))
        arch = self.core_instance.unicorndbg_instance.get_arch()
        if arch == UC_ARCH_ARM:
            self.print_arm_registers()
        else:
            print('quick registers view: arch not supported')

    def print_arm_registers(self):
        r0 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R0)
        r1 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R1)
        r2 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R2)
        r3 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R3)
        r4 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R4)
        r5 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R5)
        r6 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R6)
        r7 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R7)
        r8 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R8)
        r9 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R9)
        r10 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R10)
        r11 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R11)
        r12 = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_R12)
        sp = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_SP)
        pc = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_PC)
        lr = self.core_instance.get_emu_instance() \
            .reg_read(arm_const.UC_ARM_REG_LR)
        r = [[utils.green_bold("r0"), hex(r0), r0],
             [utils.green_bold("r1"), hex(r1), r1],
             [utils.green_bold("r2"), hex(r2), r2],
             [utils.green_bold("r3"), hex(r3), r3],
             [utils.green_bold("r4"), hex(r4), r4],
             [utils.green_bold("r5"), hex(r5), r5],
             [utils.green_bold("r6"), hex(r6), r6],
             [utils.green_bold("r7"), hex(r7), r7],
             [utils.green_bold("r8"), hex(r8), r8],
             [utils.green_bold("r9"), hex(r9), r9],
             [utils.green_bold("r10"), hex(r10), r10],
             [utils.green_bold("r11"), hex(r11), r11],
             [utils.green_bold("r12"), hex(r12), r12],
             [utils.green_bold("sp"), hex(sp), sp],
             [utils.green_bold("pc"), hex(pc), pc],
             [utils.green_bold("lr"), hex(lr), lr]]
        h = [utils.white_bold_underline('register'),
             utils.white_bold_underline('hex'),
             utils.white_bold_underline('decimal')]
        print(tabulate(r, h, tablefmt="simple"))

    def write(self, func_name, *args):
        arch = self.core_instance.unicorndbg_instance.get_arch()
        try:
            register = getattr(utils.get_arch_consts(arch), utils.get_reg_tag(arch) + str(args[0]).upper())
        except Exception as e:
            raise Exception('register not found')

        value = int(eval((args[1])))
        self.core_instance.get_emu_instance().reg_write(register, value)
        print(hex(value) + ' written into ' + str(args[0]).upper())

    def read(self, func_name, *args):
        arch = self.core_instance.unicorndbg_instance.get_arch()
        try:
            register = getattr(utils.get_arch_consts(arch), utils.get_reg_tag(arch) + str(args[0]).upper())
        except Exception as e:
            raise Exception('register not found')

        value = self.core_instance.get_emu_instance().reg_read(register)
        r = [str(args[0]).upper(), hex(value), value]
        h = [utils.white_bold_underline('register'),
             utils.white_bold_underline('hex'),
             utils.white_bold_underline('decimal')]
        print('')
        print(tabulate(r, h, tablefmt="simple"))
        print('')

    def init(self):
        pass

    def delete(self):
        pass
