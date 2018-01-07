# uDBG (WIP)

The goal is to build a sort of debugger by providing a dynamic environment based on unicorn emulator with features and commands close to GDB.
The actual code, which is a very WIP, already allow to dynamically map and unmap
memory regions, break the execution at specific addresses, write payloads into memory and alter registers during runtime.

The project is split into plug-and-play modules which can be loaded and unloaded as well during runtime.
All the modules are accessible and have a command set which allow to interact with unicorn and other modules.

All the things which came useful for the new CoC encryption reverse engineering will be some of the core feature of the tool in order to allow an easily understanding of complex and obfuscated functions.

# Commands doc

> **breakpoint**
>
> *b, bkp, break*
>
> break the emulation at specific address.
>
>     break *address

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
>     load *path *offset

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
> Manage registers or list main registers if no args.
>
>     registers [read|write]
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

## Have fun!
