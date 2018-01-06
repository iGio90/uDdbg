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
            'registers': {
                'short': 'r',
                'usage': 'registers [read|write] [...]',
                'help': 'Print registers summary if no args given',
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
                        'usage': 'registers write [register] [value]',
                        'help': 'Write value into registers',
                        'function': {
                            "context": "registers_module",
                            "f": "write"
                        }
                    },
                    'read': {
                        'short': 'r',
                        'usage': 'registers read [register]',
                        'help': 'Read specific register',
                        'function': {
                            "context": "registers_module",
                            "f": "read"
                        }
                    }
                }
            }
        }

    def registers(self, func_name, *args):
        arch = self.core_instance.unicorndbg_instance.get_arch()
        if arch == UC_ARCH_ARM:
            self.print_arm_registers()
        else:
            print('Quick registers view: arch not supported')

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
        r = [[utils.red_bold("R0"), hex(r0), r0],
             [utils.red_bold("R1"), hex(r1), r1],
             [utils.red_bold("R2"), hex(r1), r2],
             [utils.red_bold("R3"), hex(r1), r3],
             [utils.red_bold("R4"), hex(r1), r4],
             [utils.red_bold("R5"), hex(r1), r5],
             [utils.red_bold("R6"), hex(r1), r6],
             [utils.red_bold("R7"), hex(r1), r7],
             [utils.red_bold("R8"), hex(r1), r8],
             [utils.red_bold("R9"), hex(r1), r9],
             [utils.red_bold("R10"), hex(r1), r10],
             [utils.red_bold("R11"), hex(r1), r11],
             [utils.red_bold("R12"), hex(r1), r12],
             [utils.red_bold("SP"), hex(r1), sp],
             [utils.red_bold("PC"), hex(r1), pc],
             [utils.red_bold("LR"), hex(r1), lr]]
        h = [utils.green_bold('REGISTER'),
             utils.green_bold('HEX'),
             utils.green_bold('DECIMAL')]
        print(tabulate(r, h, tablefmt="rst"))

    def write(self, func_name, *args):
        arch = self.core_instance.unicorndbg_instance.get_arch()
        if arch == UC_ARCH_ARM:
            try:
                register = getattr(arm_const, "UC_ARM_REG_" + str(args[0]).upper())
                value = utils.input_to_offset(args[1])
                self.core_instance.get_emu_instance().reg_write(register, value)
            except Exception as e:
                raise Exception('Register not found')

    def init(self):
        pass

    def delete(self):
        pass
