from distutils.core import setup, Extension
extension_mod = Extension("bloom",["bloommodule.c","bloom.c"])

setup(name="bloom",ext_modules=[extension_mod])