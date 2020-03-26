#!/usr/bin/env python3
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()


def fix_setuptools():
    """
    Work around bugs in setuptools.
    Some versions of setuptools are broken and raise SandboxViolation for normal
    operations in a virtualenv. We therefore disable the sandbox to avoid these
    issues.
    """
    try:
        from setuptools.sandbox import DirectorySandbox

        def violation(operation, *args, **_):
            print("SandboxViolation: %s" % (args,))

        DirectorySandbox._violation = violation
    except ImportError:
        pass


# Fix bugs in setuptools.
fix_setuptools()

setuptools.setup(
    name="udbg",
    version="0.0.1",
    author="Giovanni Rocca and Vincenzo Greco",
    description="GDB-like debugger for Unicorn Engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/iGio90/uDdbg",
    packages=setuptools.find_packages(),
    entry_points={'console_scripts':
        [
            'uddbg = udbg.udbg:main',
        ]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent"
    ],
    install_requires=[
        'inquirer',
        'termcolor',
        'tabulate',
        'prompt-toolkit',
        'wcwidth',
        'hexdump',
        'keystone-engine',
        'capstone',
        'unicorn'
    ]
)
