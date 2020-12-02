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

from setuptools import find_packages
from setuptools import setup

setup(
    name="repokid",
    description="AWS Least Privilege for Distributed, High-Velocity Deployment",
    url="https://github.com/Netflix/repokid",
    packages=find_packages(),
    package_data={"repokid": ["py.typed"]},
    versioning="dev",
    setup_requires=["setupmeta"],
    python_requires=">=3.7",
    keywords=["aws", "iam", "access_advisor"],
    entry_points={
        "console_scripts": [
            "repokid = repokid.cli.repokid_cli:cli",
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
    zip_safe=False,
)
