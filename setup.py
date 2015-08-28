#!/usr/bin/env python
# coding: utf-8
import glob as _glob

import setuptools as _st

import tues as _tues

if __name__ == '__main__':
    _st.setup(
        name='tues',
        version=_tues.__version__,
        url='https://github.com/wontfix-org/tues/',
        license='MIT',
        author='Michael van Bracht',
        author_email='michael@wontfix.org',
        description='Easy remote command execution',
        packages=_st.find_packages(),
        scripts=_glob.glob('scripts/tues*'),
        include_package_data=True,
        platforms='any',
        setup_requires=['setuptools-markdown'],
        long_description_markdown_filename='README.md',
        install_requires=['docopt', 'fabric', 'requests>=2.4'],
        download_url='https://github.com/wontfix-org/tues/tarball/{0}'.format(_tues.__version__),
        classifiers=[
            'Programming Language :: Python',
            'Development Status :: 4 - Beta',
            'Natural Language :: English',
        ],
    )
