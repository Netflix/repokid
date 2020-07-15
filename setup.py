#     Copyright 2020 Netflix, Inc.
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

import ast
import os.path
import re

from setuptools import find_packages, setup


ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

with open("requirements.in") as f:
    REQUIRED = f.read().splitlines()

_version_re = re.compile(r"__version__\s+=\s+(.*)")
with open("repokid/__init__.py", "rb") as f:
    REPOKID_VERSION = str(
        ast.literal_eval(_version_re.search(f.read().decode("utf-8")).group(1))
    )

setup(
    name="repokid",
    version=REPOKID_VERSION,
    description="AWS Least Privilege for Distributed, High-Velocity Deployment",
    long_description=open(os.path.join(ROOT, "README.md")).read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Netflix/repokid",
    packages=find_packages(),
    install_requires=REQUIRED,
    keywords=["aws", "iam", "access_advisor"],
    entry_points={
        "console_scripts": [
            "repokid = repokid.cli.repokid_cli:main",
            "dispatcher = repokid.cli.dispatcher_cli:main",
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security",
        "Topic :: System",
        "Topic :: System :: Systems Administration",
    ],
)
