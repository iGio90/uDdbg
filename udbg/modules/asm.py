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

import capstone
import keystone

import udbg.utils as utils
from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule


class ASM(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)

        # we can hold keystone instance here
        self.keystone_instance = None
        self.ks_arch = None
        self.ks_mode = None

        self.context_name = "asm_module"
        self.command_map = {
            'dis': {
                'ref': "disassemble",
            },
            'disasm': {
                'ref': "disassemble",
            },
            'asm': {
                'ref': "assemble",
            },
            'assemble': {
                'short': 'asm',
                'function': {
                    "context": "asm_module",
                    "f": "assemble"
                },
                'help': 'assemble instructions',
                'usage': 'asm *instructions (\'mov r1, r3;add r0, r3\') [! (reset config)]'
            },
            'disassemble': {
                'short': 'dis,disasm',
                'usage': 'disasm *hex_payload [arch (arm)] [mode (thumb)]',
                'help': 'disassemble instructions',
                'function': {
                    "context": "asm_module",
                    "f": "disassemble"
                }
            },
        }

    def assemble(self, func_name, *args):
        sp = bytes(' ', 'utf8')
        instr = bytes()

        i = 0
        while i < len(args):
            a = str(args[i])
            if i == 0 and (not a.startswith("'") or not a.startswith('"')):
                raise Exception('provide a valid instruction set')
            if a.startswith("'") or a.startswith('"'):
                a = a[1:]
            b = False
            if a.endswith("'") or a.endswith('"'):
                a = a[:len(a) - 1]
                b = True
            instr += bytes(a, 'utf8')
            if not b:
                instr += sp
            i += 1
            if b:
                break

        if str(args[i]) == '!':
            self.keystone_instance = None

        if self.keystone_instance is None:
            self.ks_arch = getattr(keystone, self.prompt_ks_arch())
            self.ks_mode = getattr(keystone, self.prompt_ks_mode())

            self.core_instance.get_module('configs_module').push_config('ks_arch', self.ks_arch)
            self.core_instance.get_module('configs_module').push_config('ks_mode', self.ks_mode)

            self.keystone_instance = keystone.Ks(self.ks_arch, self.ks_mode)
        try:
            encoding, count = self.keystone_instance.asm(instr)
            h = ''
            for i in range(0, len(encoding)):
                h += hex(encoding[i])[2:]
            print("%s = %s (number of statements: %u)" % (str(instr), h, count))
        except keystone.KsError as e:
            print("ERROR: %s" % e)

    def disassemble(self, func_name, *args):
        p = bytes.fromhex(args[0])
        off = 0x00
        if len(args) == 1:
            self.internal_disassemble(p, off)
        else:
            try:
                arch = getattr(capstone.__all__, 'CS_ARCH_' + str(args[0]).upper())
            except Exception as e:
                raise Exception('arch not found')
            mode = self.core_instance.get_cs_mode()
            if len(args) > 2:
                try:
                    arch = getattr(capstone.__all__, 'CS_MODE_' + str(args[0]).upper())
                except Exception as e:
                    raise Exception('mode not found')
            cs = capstone.Cs(arch, mode)
            for i in cs.disasm(p, off):
                a = hex(i.address)
                print(utils.green_bold(a) + "\t%s\t%s" % (i.mnemonic, i.op_str))

    def internal_disassemble(self, buf, off, current_off=0):
        cs = self.core_instance.get_cs_instance()
        for i in cs.disasm(bytes(buf), off):
            if i.address == current_off:
                a = utils.red_bold(hex(i.address))
            else:
                a = utils.green_bold(hex(i.address))
            print(a + "\t%s\t%s" % ((utils.white_bold(str(i.mnemonic).upper()),
                                    str(i.op_str).upper().replace('X', 'x'))))

    def prompt_ks_arch(self):
        items = [k for k, v in keystone.__dict__.items() if not k.startswith("__") and k.startswith("KS_ARCH")]
        return utils.prompt_list(items, 'arch', 'Select arch')

    def prompt_ks_mode(self):
        items = [k for k, v in keystone.__dict__.items() if not k.startswith("__") and k.startswith("KS_MODE")]
        return utils.prompt_list(items, 'mode', 'Select mode')

    def set_ks_arch(self, arch):
        self.ks_arch = arch
        if self.ks_mode is not None:
            self.keystone_instance = keystone.Ks(self.ks_arch, self.ks_mode)

    def set_ks_mode(self, mode):
        self.ks_mode = mode
        if self.ks_arch is not None:
            self.keystone_instance = keystone.Ks(self.ks_arch, self.ks_mode)

    def init(self):
        pass

    def delete(self):
        pass
