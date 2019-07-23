import re

from capstone import *
from unicorn.unicorn_const import *

from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule

class StepOver(AbstractUnicornDbgModule):

    def __init__(self, core_instance):
        """
        create a context_name and command_map as requested from the UnicornDbgModule
        :param core_instance:
        """
        AbstractUnicornDbgModule.__init__(self, core_instance)

        self.capstone = None
        self.unicorn = None
        self.temp_brkpt = None

        self.context_name = "stepover_module"
        self.command_map = {
            'so': {
                'ref': "stepover",
            },
            'stepo': {
                'ref': "stepover",
            },
            'stepover': {
                'short': 'so,stepo',
                'function': {
                    "context": "stepover_module",
                    "f": "stepover"
                },
                'help': 'stepover'
            },
        }
        
    def hook_for_stepover(self, uc, address, size, user_data):
        if self.temp_brkpt and address == self.temp_brkpt:
            uc.emu_stop()
            self.temp_brkpt = None
            self.core_instance.unicorndbg_instance._print_context(uc, address)
    
    def stepover(self, *args):
        if not self.unicorn:
            self.unicorn = self.core_instance.unicorndbg_instance.get_emu_instance()
            self.unicorn.hook_add(UC_HOOK_CODE, self.hook_for_stepover)
        if not self.capstone:
            self.capstone = self.core_instance.get_cs_instance()
            
        dis = []
        for readlen in range(0x20, 1, -1):  # protect against going up against the end of mapped memory
            try:
                dis = self.capstone.disasm(self.unicorn.mem_read(self.core_instance.unicorndbg_instance.pc, readlen), self.core_instance.unicorndbg_instance.pc)
                dis = [i for i in dis]
                break
            except UcError:
                continue
        if len(dis) > 1:    # protection in case disassembler encounters null bytes or something
            self.temp_brkpt = dis[1].address
            self.core_instance.unicorndbg_instance.core_module.continue_exec(None)
        else:
            self.core_instance.unicorndbg_instance.core_module.next(None)
    
    def init(self):
        pass

    def delete(self):
        pass
