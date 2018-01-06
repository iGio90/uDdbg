def input_to_offset(off):
    try:
        if off.startswith('0x'):
            return int(off, 16)
        else:
            return int(off)
    except Exception as e:
        raise Exception('Invalid integer')
