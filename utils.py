import inquirer
from termcolor import colored
from unicorn import *
import capstone
from capstone import *
from unicorn import unicorn_const
import re


def error_format(command, text):
    return colored("ERR", 'red', attrs=['bold', 'underline']) + "(" + \
           colored(command, 'white', attrs=['bold', 'underline']) + "): " + text


def white_bold(text):
    return colored(text, attrs=['bold', 'dark'])


def white_bold_underline(text):
    return colored(text, attrs=['dark', 'bold', 'underline'])


def green_bold(text):
    return colored(text, 'green', attrs=['bold', 'dark'])


def red_bold(text):
    return colored(text, 'red', attrs=['bold', 'dark'])


def get_arch_consts(arch):
    if arch == UC_ARCH_ARM:
        return arm_const
    elif arch == UC_ARCH_ARM64:
        return arm64_const
    elif arch == UC_ARCH_M68K:
        return m68k_const
    elif arch == UC_ARCH_MIPS:
        return mips_const
    elif arch == UC_ARCH_SPARC:
        return sparc_const
    elif arch == UC_ARCH_X86:
        return x86_const


def get_reg_tag(arch):
    if arch == UC_ARCH_ARM:
        return "UC_ARM_REG_"
    elif arch == UC_ARCH_ARM64:
        return "UC_ARM64_REG_"
    elif arch == UC_ARCH_M68K:
        return "UC_M68K_REG_"
    elif arch == UC_ARCH_MIPS:
        return "UC_MIPS_REG_"
    elif arch == UC_ARCH_SPARC:
        return "UC_SPARC_REG_"
    elif arch == UC_ARCH_X86:
        return "UC_X86_REG_"


def prompt_list(items, key, hint):
    base_path = [
        inquirer.List(key,
                      message=hint,
                      choices=items)]
    r = inquirer.prompt(base_path)
    return r[key]


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


def check_args(pattern, args):
    """
    check that args array matches the pattern type and args len
    :param pattern: string with args type pattern. [int|str|hex], Ex. int int hex.
    :param args: args array to check
    :return:
    """
    # get the pattern array
    p_arr = pattern.split(' ')
    args_effective_len = 0

    for i, p in enumerate(p_arr):
        if indexof(p, '@') == -1:
            args_effective_len += 1

    # if args len doesn't match with the pattern
    if len(args) < args_effective_len or len(args) > len(p_arr):
        return False, "args len doesn't match"

    # int str hex
    for i, arg in enumerate(args):
        if arg == '':
            return False, "arg " + str(i) + " is empty"

        # if we have optional args
        if indexof(p_arr[i], '@') != -1:
            p_arr[i] = p_arr[i][1:]

        # select the right regex for the pattern
        if p_arr[i] == "int":
            reg = r"\d+"
        elif p_arr[i] == "str":
            reg = r".+"
        elif p_arr[i] == "hex":
            reg = r"0x\d+"
        elif p_arr[i] == "hexsum":
            reg = r"0x\d+\+0x\d+"
        elif p_arr[i] == "intsum":
            reg = r"\d+\+\d+"
        else:
            return False, "pattern " + str(i) + " wrong type"

        if re.match(reg, arg) is None:
            return False, "arg " + str(i) + " should be " + p_arr[i] + " type"

    return True, None


def indexof(str, str_search):
    try:
        if str.index(str_search):
            return str.index(str_search)
    except Exception:
        return -1
