#############################################################################
#
#    Copyright (C) 2018
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

from tabulate import tabulate
from unicorn import *
from unicorn.x86_const import *

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
        arch = self.core_instance.unicorndbg_instance.arch
        mode = self.core_instance.unicorndbg_instance.mode
        if arch == UC_ARCH_ARM:
            self.print_arm_registers()
        if arch == UC_ARCH_X86:
            if mode == UC_MODE_16:
                self.print_x86_16_registers()
            elif mode == UC_MODE_32:
                self.print_x86_registers()
            else:
                # If mode is none of the above, let's assume x64.
                self.print_x64_registers()
        else:
            print('quick registers view: arch not supported')

    @property
    def emu_instance(self):
        return self.core_instance.get_emu_instance()

    def reg(self, name: str, uc_const: int):
        """
        Create an entry for a new reg, reading the contents from unicorn.
        """
        uc = self.emu_instance
        val = uc.reg_read(uc_const)
        return [utils.green_bold(name), hex(val), val]
         
    def print_x86_16registers(self):
        r = [
            self.reg("ip", UC_X86_REG_IP),
            self.reg("di", UC_X86_REG_DI),
            self.reg("si", UC_X86_REG_SI),
            self.reg("ax", UC_X86_REG_AX),
            self.reg("bx", UC_X86_REG_BX),
            self.reg("cx", UC_X86_REG_CX),
            self.reg("dx", UC_X86_REG_DX),
            self.reg("sp", UC_X86_REG_SP),
            self.reg("bp", UC_X86_REG_BP),
            self.reg("eflags", UC_X86_REG_EFLAGS),
            self.reg("cs", UC_X86_REG_CS),
            self.reg("gs", UC_X86_REG_GS),
            self.reg("fs", UC_X86_REG_FS),
            self.reg("ss", UC_X86_REG_SS),
            self.reg("ds", UC_X86_REG_DS),
            self.reg("es", UC_X86_REG_ES)
        ]

        h = [utils.white_bold_underline('register'),
             utils.white_bold_underline('hex'),
             utils.white_bold_underline('decimal')]
        print(tabulate(r, h, tablefmt="simple"))



    def print_x86_registers(self):
        r = [
            self.reg("eip", UC_X86_REG_EIP),
            self.reg("edi", UC_X86_REG_EDI),
            self.reg("esi", UC_X86_REG_ESI),
            self.reg("eax", UC_X86_REG_EAX),
            self.reg("ebx", UC_X86_REG_EBX),
            self.reg("ecx", UC_X86_REG_ECX),
            self.reg("edx", UC_X86_REG_EDX),
            self.reg("esp", UC_X86_REG_ESP),
            self.reg("ebp", UC_X86_REG_EBP),
            self.reg("eflags", UC_X86_REG_EFLAGS),
            self.reg("cs", UC_X86_REG_CS),
            self.reg("gs", UC_X86_REG_GS),
            self.reg("fs", UC_X86_REG_FS),
            self.reg("ss", UC_X86_REG_SS),
            self.reg("ds", UC_X86_REG_DS),
            self.reg("es", UC_X86_REG_ES)
        ]

        h = [utils.white_bold_underline('register'),
             utils.white_bold_underline('hex'),
             utils.white_bold_underline('decimal')]
        print(tabulate(r, h, tablefmt="simple"))


    def print_x64_registers(self):
        GSMSR = 0xC0000101
        FSMSR = 0xC0000100
        # TODO: Find a way to read FS and GSBASE without clobbering memory.
        #return get_msr(uc, GSMSR)
        #return get_msr(uc, FSMSR)

        r = [
            self.reg("rip", UC_X86_REG_RIP),
            self.reg("rdi", UC_X86_REG_RDI),
            self.reg("rsi", UC_X86_REG_RSI),
            self.reg("rax", UC_X86_REG_RAX),
            self.reg("rbx", UC_X86_REG_RBX),
            self.reg("rcx", UC_X86_REG_RCX),
            self.reg("rdx", UC_X86_REG_RDX),
            self.reg("rsp", UC_X86_REG_RSP),
            self.reg("rbp", UC_X86_REG_RBP),
            self.reg("r8", UC_X86_REG_R8),
            self.reg("r9", UC_X86_REG_R9),
            self.reg("r10", UC_X86_REG_R10),
            self.reg("r11", UC_X86_REG_R11),
            self.reg("r12", UC_X86_REG_R12),
            self.reg("r13", UC_X86_REG_R13),
            self.reg("r14", UC_X86_REG_R14),
            self.reg("r15", UC_X86_REG_R15),
            self.reg("eflags", UC_X86_REG_EFLAGS),
        ]

        h = [utils.white_bold_underline('register'),
             utils.white_bold_underline('hex'),
             utils.white_bold_underline('decimal')]
        print(tabulate(r, h, tablefmt="simple"))


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

        value = utils.u_eval(self.core_instance, args[1])
        self.core_instance.get_emu_instance().reg_write(register, value)
        print(hex(value) + ' written into ' + str(args[0]).upper())

    def read(self, func_name, *args):
        reg = str(args[0]).upper()
        value = self.read_register(reg)
        if value is None:
            raise Exception('register not found')

        r = [[utils.green_bold(reg), hex(value), str(value)]]
        h = [utils.white_bold_underline('register'),
             utils.white_bold_underline('hex'),
             utils.white_bold_underline('decimal')]
        print('')
        print(tabulate(r, h, tablefmt="simple"))
        print('')

    def read_register(self, reg):
        arch = self.core_instance.unicorndbg_instance.get_arch()
        try:
            register = getattr(utils.get_arch_consts(arch), utils.get_reg_tag(arch) + reg)
        except Exception as e:
            return None
        return self.core_instance.get_emu_instance().reg_read(register)

    def init(self):
        pass

    def delete(self):
        pass
