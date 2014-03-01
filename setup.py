#! /usr/bin/env python
from distutils.core import setup, Extension

m = Extension('ptrace',
        sources = ['ptrace.c'] 
        )


setup(name = 'ptrace',
        version = '1.0',
        description = 'python native library for ptrace',
        ext_modules = [m])
