#!/usr/bin/env python
# coding: utf-8

import glob as _glob

import setuptools as _st


if __name__ == "__main__":
    _st.setup(
        name="tues",
        version="2.1.0",
        url="https://github.com/wontfix-org/tues/",
        license="MIT",
        author="Michael van Bracht",
        author_email="michael@wontfix.org",
        description="Easy remote command execution",
        packages=_st.find_packages(),
        scripts=_glob.glob("scripts/tues*"),
        include_package_data=True,
        platforms="any",
        install_requires=["click", "asyncssh", "async-timeout", "requests>=2.4", "setuptools"],
        classifiers=[
            "Natural Language :: English",
            "Programming Language :: Python :: 3",
        ],
        requires_python=">=3.7",
    )
