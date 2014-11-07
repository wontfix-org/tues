#!/usr/bin/env python
# coding: utf-8
import os as _os
import io as _io
import glob as _glob

import setuptools as _st

here = _os.path.abspath(_os.path.dirname(__file__))

def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        with _io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)


long_description = read('README.txt', 'CHANGES.txt')


if __name__ == '__main__':
    _st.setup(
        name='tues',
        version="0.0.1",
        url='http://github.com/wontfix-org/tues/',
        license='Apache Software License',
        author='Michael van Bracht',
        author_email='michael@wontfix.org',
        description='Easy remote command execution',
        long_description=long_description,
        packages=_st.find_packages(),
        scripts=_glob.glob('scripts/tues*'),
        include_package_data=True,
        platforms='any',
        install_requires=['docopt', 'fabric', 'requests'],
        classifiers=[
            'Programming Language :: Python',
            'Development Status :: 4 - Beta',
            'Natural Language :: English',
        ],
    )
