# uDdbg - Unicorn DOPE Debugger

A gdb like debugger that provide a runtime env to unicorn emulator and additionals features!
## Get in touch
* https://discord.gg/hTVhy3V
* https://twitter.com/iGio90

# Commands doc

> **assemble**
>
> *asm*
>
> assemble instructions.
>
>     asm *instructions ('mov r1, r3;add r0, r3, r2') [! (trigger arch/mode)]

***

> **breakpoint**
>
> *b, bkp, break*
>
> break the emulation at specific address.
>
>     break *address

***

> **configs**
>
> print list of configs.
>
>     configs

***

> **continue**
>
> *c*
>
> start / continue emulation.
>
>     continue

***

> **delete**
>
> *d*
>
> remove breakpoint at address.
>
>     d *address

***

> **disassemble**
>
> *dis, disasm*
>
> disassemble instructions.
>
>     disasm *hex_payload [arch (arm)] [mode (thumb)]

***

> **executors**
>
> *e, ex, exec*
>
> manage executors.
>
>     exec [delete|load|new|run|save]

***

> **help**
>
> *h*
>
> print specific command help or general if none provided.
>
>     help [*cmd]

***

> **load**
>
> *lb*
>
> load and map binary from file.
>
>     load *file_path *offset

***

> **map**
>
> list mappings.
>
>     map
>

***

> **memory**
>
> *m*
>
> memory operations.
>
>     memory [dump|fwrite|map|read|write|unmap]
>

***

> **modules**
>
> list enabled modules.
>
>     modules
>

***

> **next**
>
> *n, ni*
>
> step instruction.
>
>     next
>

***

> **patch**
>
> *p*
>
> manage patches.
>
>     patch [list|add|remove|toggle]
>

***

> **quit**
>
> *q*
>
> quit udbg.
>
>     quit
>

***

> **registers**
>
> *r, reg, regs*
>
> manage registers or list main registers if no args.
>
>     registers [read|write]
>

***

> **restore**
>
> set emulator to entry address and restore initial memory context.
>
>     restore
>

***

> **set**
>
> set configuration.
>
>     set *config_name *value
>

***

# Sub command examples

Some of the main command listed above have nested commands, I.E memory

> **memory**
>
> *m*
>
> memory operations.
>
>     memory [dump|read|write]
>

Using ``help memory`` or any other command will print an help of the nested commands:

    Help for: memory
    memory operations
    usage: memory [dump|read|write] [...]

    command    short    usage
    ---------  -------  ----------------------------------------------------
    dump       d        memory dump *offset *length *file_path
    read       r        memory read *offset *length [format: h|i]
    write      w        memory write *offset *hex_payload

Nested commands have shortcuts as well so:

```memory write 0x10000 0x00BF```

is equal to:

```m w 0x10000 0x00BF```

# Other examples

```load binary 0xea783000```

or

```load binary 0xea780000+0x3000```

break executions

```b 0xeb104c4```

continue

```c```

read registers

```registers```

write something into r2

```r w r2 0x20```

assemble an instruction set

```asm 'mov r2, r1;add r1, r0, r3'```

write something into memory

```m w 0xeb104c4 00BF00BF000000FFFFFF```

read instructions

```memory read 0xeb104c4 256 i```

or

```m r 0xeb104c4 256 i```

# Have fun!

Copyright (C) 2018
Giovanni -iGio90- Rocca, Vincenzo -rEDSAMK- Greco

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
