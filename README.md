# uDBG (WIP)

The goal is to build a sort of debugger by providing a dynamic environment based on unicorn emulator with features and commands close to GDB.
The actual code, which is a very WIP, already allow to dynamically map and unmap
memory regions, break the execution at specific addresses, write payloads into memory and alter registers during runtime.

The project is split into plug-and-play modules which can be loaded and unloaded as well during runtime.
All the modules are accessible and have a command set which allow to interact with unicorn and other modules.

All the things which came useful for the new CoC encryption reverse engineering will be some of the core feature of the tool in order to allow an easily understanding of complex and obfuscated functions.

type ``help`` or ``help [any command]`` to have an idea.