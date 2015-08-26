# -*- coding: utf-8 -*-
# Licensed to the StackStorm, Inc ('StackStorm') under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from setuptools import setup, find_packages

from dist_utils import check_pip_version
from dist_utils import fetch_requirements

check_pip_version()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS_FILE = os.path.join(BASE_DIR, 'requirements.txt')

install_reqs, dep_links = fetch_requirements(REQUIREMENTS_FILE)

setup(
    name='st2-auth-backend-ldap',
    version='0.1.0',
    description='StackStorm authentication backend which reads credentials from a LDAP server.',
    author='StackStorm, Inc.',
    author_email='info@stackstorm.com',
    url='https://github.com/StackStorm/st2-auth-backend-ldap',
    license='Apache License (2.0)',
    download_url='https://github.com/StackStorm/st2-auth-backend-ldap/tarball/master',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Intended Audience :: Developers',
        'Environment :: Console',
    ],
    platforms=['Any'],
    scripts=[],
    provides=['st2auth_ldap_backend'],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_reqs,
    dependency_links=dep_links,
    test_suite='tests',
    entry_points={
        'st2auth.backends.backend': [
            'ldap = st2auth_ldap_backend.ldap:LDAPAuthenticationBackend',
        ],
    },
    zip_safe=False
)
