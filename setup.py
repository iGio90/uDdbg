import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="udbg",
    version="0.0.1",
    author="Giovanni Rocca and Vincenzo Greco",
    description="GDB-like debugger for Unicorn Engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/iGio90/uDdbg",
    packages=setuptools.find_packages(),
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
        'hexdump',
        'keystone-engine',
        'capstone',
        'unicorn'
    ]
)
