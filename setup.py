#     Copyright 2017 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
import re
import ast
from setuptools import setup, find_packages

with open('requirements.txt') as f:
    REQUIRED = f.read().splitlines()

_version_re = re.compile(r'__version__\s+=\s+(.*)')
with open('repokid/__init__.py', 'rb') as f:
    REPOKID_VERSION = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

setup(
    name='repokid',
    version=REPOKID_VERSION,
    description='AWS Least Privilege for Distributed, High-Velocity Deployment',
    # removed as I think getting long_desc to work is perhaps outside the scope
    # of this PR, other long_desc's I've seen have used .rst to display on
    # Pypi, so I think that may be necessary also.
    # long_description=open("readme.md").read(),
    url='https://github.com/Netflix/repokid',
    packages=find_packages(),
    install_requires=REQUIRED,
    keywords=['aws', 'iam', 'access_advisor'],
    entry_points={
        'console_scripts': [
            'repokid = repokid.cli.repokid_cli:main',
            'dispatcher = repokid.cli.dispatcher_cli:main'
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: System',
        'Topic :: System :: Systems Administration'
        ]
)
