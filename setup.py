#!/usr/bin/env python
# coding: utf-8
import glob as _glob

import setuptools as _st


if __name__ == '__main__':
    _st.setup(
        name='tues',
        version="0.0.1",
        url='http://github.com/wontfix-org/tues/',
        license='Apache Software License',
        author='Michael van Bracht',
        author_email='michael@wontfix.org',
        description='Easy remote command execution',
        packages=_st.find_packages(),
        scripts=_glob.glob('scripts/tues*'),
        include_package_data=True,
        platforms='any',
        install_requires=['docopt', 'fabric', 'requests>=2.4'],
        classifiers=[
            'Programming Language :: Python',
            'Development Status :: 4 - Beta',
            'Natural Language :: English',
        ],
    )
