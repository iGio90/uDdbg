from termcolor import colored


def input_to_offset(off):
    try:
        if off.startswith('0x'):
            return int(off, 16)
        else:
            return int(off)
    except Exception as e:
        raise Exception('Invalid integer')


def green_bold(text):
    return colored(text, 'green', attrs=['bold', 'dark'])


def red_bold(text):
    return colored(text, 'red', attrs=['bold', 'dark'])
