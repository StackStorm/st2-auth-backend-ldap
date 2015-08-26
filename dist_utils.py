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

import sys

from distutils.version import StrictVersion

GET_PIP = 'curl https://bootstrap.pypa.io/get-pip.py | python'

try:
    import pip
    from pip.req import parse_requirements
except ImportError:
    print('Download pip:\n', GET_PIP)
    sys.exit(1)

__all__ = [
    'check_pip_version',
    'fetch_requirements'
]


def check_pip_version():
    """
    Ensure that a minimum supported version of pip is installed.
    """
    if StrictVersion(pip.__version__) < StrictVersion('6.0.0'):
        print("Upgrade pip, your version `{0}' "
              "is outdated:\n{1}".format(pip.__version__, GET_PIP))
        sys.exit(1)


def fetch_requirements(requirements_file_path):
    """
    Return a list of requirements and links by parsing the provided requirements file.
    """
    links = []
    reqs = []
    for req in parse_requirements(requirements_file_path, session=False):
        if getattr(req, 'link', None):
            links.append(str(req.link))
        reqs.append(str(req.req))
    return (reqs, links)
