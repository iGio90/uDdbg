from unicorn.unicorn_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *
from unicorn.sparc_const import *
from unicorn.m68k_const import *
from capstone import *

_stringToUnicorn = {
    "amd64":        (UC_ARCH_X86, UC_MODE_64),
    "x86":          (UC_ARCH_X86, UC_MODE_32),
    "i8086":        (UC_ARCH_X86, UC_MODE_16),
    "arm64be":      (UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_BIG_ENDIAN),
    "arm64le":      (UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN),
    "armbe":        (UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN),
    "armle":        (UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN),
    "armbethumb":   (UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_BIG_ENDIAN),
    "armlethumb":   (UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN),
    "mips":         (UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN),
    "mipsel":       (UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN),
    "mips64":       (UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN),
    "mips64el":     (UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_LITTLE_ENDIAN),
    "powerpc":      (UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN),
    "sparc64":      (UC_ARCH_SPARC, UC_MODE_SPARC64 | UC_MODE_BIG_ENDIAN),
    "sparc":        (UC_ARCH_SPARC, UC_MODE_SPARC32 | UC_MODE_BIG_ENDIAN),
    "m68k":         (UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
}
_stringToUnicorn["x64"] = _stringToUnicorn["amd64"]
_stringToUnicorn["x86-64"] = _stringToUnicorn["amd64"]
_stringToUnicorn["i386:x86-64"] = _stringToUnicorn["amd64"]
_stringToUnicorn["i386"] = _stringToUnicorn["x86"]
_stringToUnicorn["powerpc:common"] = _stringToUnicorn["powerpc"]
_stringToUnicorn["sparc:v9"] = _stringToUnicorn["sparc64"]

_stringToCapstone = {
    "amd64":        (CS_ARCH_X86, CS_MODE_64),
    "x86":          (CS_ARCH_X86, CS_MODE_32),
    "i8086":        (CS_ARCH_X86, CS_MODE_16),
    "arm64be":      (CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_BIG_ENDIAN),
    "arm64le":      (CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN),
    "armbe":        (CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN),
    "armle":        (CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN),
    "armbethumb":   (CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN),
    "armlethumb":   (CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN),
    "mips":         (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN),
    "mipsel":       (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN),
    "mips64":       (CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN),
    "mips64el":     (CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN),
    "powerpc":      (CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN),
    "sparc64":      (CS_ARCH_SPARC, CS_MODE_V9 | CS_MODE_BIG_ENDIAN),
    "sparc":        (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN),
    "m68k":         (CS_ARCH_M68K, CS_MODE_BIG_ENDIAN)
}
_stringToCapstone["x64"] = _stringToCapstone["amd64"]
_stringToCapstone["x86-64"] = _stringToCapstone["amd64"]
_stringToCapstone["i386:x86-64"] = _stringToCapstone["amd64"]
_stringToCapstone["i386"] = _stringToCapstone["x86"]
_stringToCapstone["powerpc:common"] = _stringToCapstone["powerpc"]
_stringToCapstone["sparc:v9"] = _stringToCapstone["sparc64"]

_arm32_regtable = {
    UC_ARM_REG_R0: "r0",
    UC_ARM_REG_R1: "r1",
    UC_ARM_REG_R2: "r2",
    UC_ARM_REG_R3: "r3",
    UC_ARM_REG_R4: "r4",
    UC_ARM_REG_R5: "r5",
    UC_ARM_REG_R6: "r6",
    UC_ARM_REG_R7: "r7",
    UC_ARM_REG_R8: "r8",
    UC_ARM_REG_R9: "r9",
    UC_ARM_REG_R10: "r10",
    UC_ARM_REG_FP: "r11",
    UC_ARM_REG_IP: "r12",
    UC_ARM_REG_SP: "sp",
    UC_ARM_REG_LR: "lr",
    UC_ARM_REG_PC: "pc",
    UC_ARM_REG_CPSR: "cpsr"
}

_arm64_regtable = {
    UC_ARM64_REG_X0: "x0",
    UC_ARM64_REG_X1: "x1",
    UC_ARM64_REG_X2: "x2",
    UC_ARM64_REG_X3: "x3",
    UC_ARM64_REG_X4: "x4",
    UC_ARM64_REG_X5: "x5",
    UC_ARM64_REG_X6: "x6",
    UC_ARM64_REG_X7: "x7",
    UC_ARM64_REG_X8: "x8",
    UC_ARM64_REG_X9: "x9",
    UC_ARM64_REG_X10: "x10",
    UC_ARM64_REG_X11: "x11",
    UC_ARM64_REG_X12: "x12",
    UC_ARM64_REG_X13: "x13",
    UC_ARM64_REG_X14: "x14",
    UC_ARM64_REG_X15: "x15",
    UC_ARM64_REG_X16: "x16",
    UC_ARM64_REG_X17: "x17",
    UC_ARM64_REG_X18: "x18",
    UC_ARM64_REG_X19: "x19",
    UC_ARM64_REG_X20: "x20",
    UC_ARM64_REG_X21: "x21",
    UC_ARM64_REG_X22: "x22",
    UC_ARM64_REG_X23: "x23",
    UC_ARM64_REG_X24: "x24",
    UC_ARM64_REG_X25: "x25",
    UC_ARM64_REG_X26: "x26",
    UC_ARM64_REG_X27: "x27",
    UC_ARM64_REG_X28: "x28",
    UC_ARM64_REG_PC: "pc",
    UC_ARM64_REG_SP: "sp",
    UC_ARM64_REG_FP: "fp",
    UC_ARM64_REG_LR: "lr",
    UC_ARM64_REG_NZCV: "nzcv",
    UC_ARM_REG_CPSR: "cpsr"
}

_i8086_regtable = {
    UC_X86_REG_IP: "ip",
    UC_X86_REG_DI: "di",
    UC_X86_REG_SI: "si",
    UC_X86_REG_AX: "ax",
    UC_X86_REG_BX: "bx",
    UC_X86_REG_CX: "cx",
    UC_X86_REG_DX: "dx",
    UC_X86_REG_SP: "sp",
    UC_X86_REG_BP: "bp",
    UC_X86_REG_EFLAGS: "eflags",
    UC_X86_REG_CS: "cs",
    UC_X86_REG_GS: "gs",
    UC_X86_REG_FS: "fs",
    UC_X86_REG_SS: "ss",
    UC_X86_REG_DS: "ds",
    UC_X86_REG_ES: "es"
}

_x86_regtable = {
    UC_X86_REG_EAX: "eax",
    UC_X86_REG_ECX: "ecx",
    UC_X86_REG_EDX: "edx",
    UC_X86_REG_EBX: "ebx",
    UC_X86_REG_ESP: "esp",
    UC_X86_REG_EBP: "ebp",
    UC_X86_REG_ESI: "esi",
    UC_X86_REG_EDI: "edi",
    UC_X86_REG_EIP: "eip",
    UC_X86_REG_EFLAGS: "eflags",
    UC_X86_REG_CS: "cs",
    UC_X86_REG_SS: "ss",
    UC_X86_REG_DS: "ds",
    UC_X86_REG_ES: "es",
    UC_X86_REG_FS: "fs",
    UC_X86_REG_GS: "gs"
}

_amd64_regtable = {
    UC_X86_REG_RAX: "rax",
    UC_X86_REG_RBX: "rbx",
    UC_X86_REG_RCX: "rcx",
    UC_X86_REG_RDX: "rdx",
    UC_X86_REG_RSI: "rsi",
    UC_X86_REG_RDI: "rdi",
    UC_X86_REG_RBP: "rbp",
    UC_X86_REG_RSP: "rsp",
    UC_X86_REG_R8: "r8",
    UC_X86_REG_R9: "r9",
    UC_X86_REG_R10: "r10",
    UC_X86_REG_R11: "r11",
    UC_X86_REG_R12: "r12",
    UC_X86_REG_R13: "r13",
    UC_X86_REG_R14: "r14",
    UC_X86_REG_R15: "r15",
    UC_X86_REG_RIP: "rip",
    UC_X86_REG_EFLAGS: "rflags",
    UC_X86_REG_CS: "cs",
    UC_X86_REG_SS: "ss",
    UC_X86_REG_DS: "ds",
    UC_X86_REG_ES: "es",
    UC_X86_REG_FS: "fs",
    UC_X86_REG_GS: "gs"
}

_mips_regtable = {
    UC_MIPS_REG_ZERO: "0",
    UC_MIPS_REG_AT: "at",
    UC_MIPS_REG_V0: "v0",
    UC_MIPS_REG_V1: "v1",
    UC_MIPS_REG_A0: "a0",
    UC_MIPS_REG_A1: "a1",
    UC_MIPS_REG_A2: "a2",
    UC_MIPS_REG_A3: "a3",
    UC_MIPS_REG_T0: "t0",
    UC_MIPS_REG_T1: "t1",
    UC_MIPS_REG_T2: "t2",
    UC_MIPS_REG_T3: "t3",
    UC_MIPS_REG_T4: "t4",
    UC_MIPS_REG_T5: "t5",
    UC_MIPS_REG_T6: "t6",
    UC_MIPS_REG_T7: "t7",
    UC_MIPS_REG_S0: "s0",
    UC_MIPS_REG_S1: "s1",
    UC_MIPS_REG_S2: "s2",
    UC_MIPS_REG_S3: "s3",
    UC_MIPS_REG_S4: "s4",
    UC_MIPS_REG_S5: "s5",
    UC_MIPS_REG_S6: "s6",
    UC_MIPS_REG_S7: "s7",
    UC_MIPS_REG_T8: "t8",
    UC_MIPS_REG_T9: "t9",
    UC_MIPS_REG_K0: "k0",
    UC_MIPS_REG_K1: "k1",
    UC_MIPS_REG_GP: "gp",
    UC_MIPS_REG_SP: "sp",
    UC_MIPS_REG_S8: "s8",
    UC_MIPS_REG_RA: "ra",
    UC_MIPS_REG_LO: "lo",
    UC_MIPS_REG_HI: "hi",
    UC_MIPS_REG_PC: "pc"
}

def getUnicornSetup(archstring: str):
    return _stringToUnicorn[archstring]
    
def getCapstoneSetup(archstring: str):
    return _stringToCapstone[archstring]
    
def getArchString(ucarch: int, ucmode: int):
    for archstring in _stringToUnicorn:
        setting = _stringToUnicorn[archstring]
        if setting[0] == ucarch and setting[1] == ucmode:
            return archstring
    raise KeyError((ucarch, ucmode))
    
def getEndianness(archstring: str):
    mode = _stringToUnicorn[archstring][1]
    if mode & UC_MODE_BIG_ENDIAN:
        return "big"
    else:   # encoding for UC_MODE_LITTLE_ENDIAN is 0 so this is the best way to test that
        return "little"
    
def getRegStringTable(archstring: str):
    if      archstring == "armbe" or \
            archstring == "armle" or \
            archstring == "armbethumb" or \
            archstring == "armlethumb":
        return _arm32_regtable
    elif    archstring == "arm64be" or \
            archstring == "arm64le":
        return _arm64_regtable
    elif    archstring == "mips" or \
            archstring == "mipsel" or \
            archstring == "mips64" or \
            archstring == "mips64el":
        return _mips_regtable
    elif    archstring == "i8086":
        return _i8086_regtable
    elif    archstring == "x86" or \
            archstring == "i386":
        raise NotImplementedError
    elif    archstring == "amd64" or \
            archstring == "x64" or \
            archstring == "x86-64" or \
            archstring == "i386:x86-64":
        return _amd64_regtable
    elif    archstring == "powerpc" or \
            archstring == "powerpc:common":
        # Unicorn doesn't seem to fully support PowerPC
        raise NotImplementedError
    elif    archstring == "sparc64" or \
            archstring == "sparc:v9":
        raise NotImplementedError
    elif    archstring == "sparc":
        raise NotImplementedError
    elif    archstring == "m68k":
        raise NotImplementedError
    
def getPCCode(archstring: str):
    if      archstring == "armbe" or \
            archstring == "armle" or \
            archstring == "armbethumb" or \
            archstring == "armlethumb":
        return UC_ARM_REG_PC
    elif    archstring == "arm64be" or \
            archstring == "arm64le":
        return UC_ARM64_REG_PC
    elif    archstring == "mips" or \
            archstring == "mipsel" or \
            archstring == "mips64" or \
            archstring == "mips64el":
        return UC_MIPS_REG_PC
    elif    archstring == "i8086":
        return UC_X86_REG_IP
    elif    archstring == "x86" or \
            archstring == "i386":
        return UC_X86_REG_EIP
    elif    archstring == "amd64" or \
            archstring == "x64" or \
            archstring == "x86-64" or \
            archstring == "i386:x86-64":
        return UC_X86_REG_RIP
    elif    archstring == "powerpc" or \
            archstring == "powerpc:common":
        # Unicorn doesn't seem to fully support PowerPC
        raise NotImplementedError
    elif    archstring == "sparc64" or \
            archstring == "sparc:v9" or \
            archstring == "sparc":
        return UC_SPARC_REG_PC
    elif    archstring == "m68k":
        return UC_M68K_REG_PC
