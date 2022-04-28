#############################################################################
#
#    Copyright (C) 2022
#    Merlin Danner <merlin.danner@posteo.net>
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
#
#############################################################################

from tabulate import tabulate

import udbg.utils as utils
from udbg.modules.unicorndbgmodule import AbstractUnicornDbgModule


class Labels(AbstractUnicornDbgModule):
    def __init__(self, core_instance):
        AbstractUnicornDbgModule.__init__(self, core_instance)
        self.labels = []
        self.labels_by_address = {}
        self.labels_by_name = {}
        self.context_name = "labels_module"
        self.command_map = {
            'l': {
                'ref': 'label',
            },
            'label': {
                'short': 'l',
                'help': 'label operations',
                'usage': 'label [list|at_address|address] [...]',
                'sub_commands': {
                    'l': {
                        'ref': 'list',
                    },
                    'aa': {
                        'ref': 'at_address',
                    },
                    'a': {
                        'ref': 'address',
                    },
                    'list': {
                        'short': 'l',
                        'usage': 'label list',
                        'help': 'list known labels',
                        'function': {
                            'context': 'labels_module',
                            'f': 'list'
                        }
                    },
                    'at_address': {
                        'short': 'aa',
                        'usage': 'label at_address *address',
                        'help': 'prints the label at_address *address',
                        'function': {
                            'context': 'labels_module',
                            'f': 'at_address'
                        }
                    },
                    'address': {
                        'short': 'a',
                        'usage': 'label address *labelname',
                        'help': 'prints the address of *labelname',
                        'function': {
                            'context': 'labels_module',
                            'f': 'address'
                        }
                    },
                }
            }
        }

    def add_ghidra_csv_labels_path(self, filepath: str):
        import csv
        with open(filepath, 'r', newline='') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            for row in csv_reader:
                self.add((row['Name'], int(row['Location'], base=16)))

    def list(self, func_name, *args):
        print(utils.titlify('labels'))
        h = [utils.white_bold_underline('name'),
             utils.white_bold_underline('address')]
        print('')
        print(tabulate(self.labels, h, tablefmt="simple"))
        print('')

    def add(self, label_tuple):
        label = [label_tuple[0], hex(label_tuple[1])]
        self.labels.append(label)
        self.labels_by_name[label_tuple[0]] = label
        self.labels_by_address[label_tuple[1]] = label

    def get_labels(self):
        return self.labels

    def get_address(self, label_name):
        try:
            return self.labels_by_name[label_name][1]
        except KeyError:
            return None

    def search_label(self, address):
        try:
            return self.labels_by_address[address]
        except KeyError:
            return None

    def address(self, funcname, *args):
        label_name = args[0]
        if label_name[0] != '&':
            label_name = '&' + label_name
        print('label {} at address {}'.format(label_name.lstrip('&'), hex(utils.u_eval(self.core_instance, label_name))))

    def at_address(self, funcname, *args):
        address = utils.u_eval(self.core_instance, args[0])
        label = self.search_label(address)
        if label:
            print('label {} at address {}'.format(label[0], label[1]))
        else:
            print('No label found at address ', address)

    def init(self):
        pass

    def delete(self):
        pass
