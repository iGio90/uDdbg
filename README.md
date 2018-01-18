# uDdbg (WIP)

The goal is to build a sort of debugger by providing a dynamic environment based on unicorn emulator with features and commands close to GDB.
The actual code, which is a very WIP, already allow to dynamically map and unmap
memory regions, break the execution at specific addresses, write payloads into memory and alter registers during runtime.

The project is split into plug-and-play modules which can be loaded and unloaded as well during runtime.
All the modules are accessible and have a command set which allow to interact with unicorn and other modules.

All the things which came useful for the new CoC encryption reverse engineering will be some of the core feature of the tool in order to allow an easily understanding of complex and obfuscated functions.

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
> manage mappings.
>
>     map [list|map|unamp]
>

***

> **memory**
>
> *m*
>
> memory operations.
>
>     memory [dump|read|write]
>

***

> **modules**
>
> list enabled modules.
>
>     modules
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
> Manageset emulator to entry address and restore initial memory context.
>
>     registers [read|write]
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
