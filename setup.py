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
import os.path
import sys
from setuptools import setup, find_packages

_version_re = re.compile(r'__version__\s+=\s+(.*)')
with open('repokid/__init__.py', 'rb') as f:
    REPOKID_VERSION = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

# When executing the setup.py, we need to be able to import ourselves.  This
# means that we need to add the src/ directory to the sys.path

sys.path.insert(0, ROOT)

setup(
    name='repokid',
    version=REPOKID_VERSION,
    long_description=__doc__,
    packages=find_packages(),
    install_requires=[
        'boto3==1.4.4',
        'cloudaux==1.2.0',
        'docopt==0.6.2',
        'import_string==0.1.0',
        'policyuniverse==1.0.6.2',
        'requests==2.13.0',
        'tabulate==0.7.7',
        'tabview==1.4.2',
        'tqdm==4.11.2'
    ],
    entry_points={
        'console_scripts': [
            'repokid = repokid.repokid:main',
            'repokid_reactor = repokid.repokid_reactor:main'
        ],
    }
)
