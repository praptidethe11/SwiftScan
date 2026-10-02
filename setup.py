#! /usr/bin/env python3
from setuptools import setup
import pathlib

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text(encoding="utf-8")

setup(
    name="SwiftScan",
    version="1.3",
    description="The Multi-Tool Web Vulnerability Scanner.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/praptidethe11/SwiftScan.git",
    py_modules=["swiftscan", "swiftscan_logging", "api_sources", "web_app"],
    # The command-line scanner only uses the standard library. Flask/gunicorn
    # are needed for the web UI (`pip install .[web]`). The web UI loads
    # templates/ from the source tree, so run it from a checkout or the Docker
    # image rather than from a wheel.
    install_requires=[],
    extras_require={
        "web": [
            "flask>=3.0,<4",
            "gunicorn>=22,<24; sys_platform != 'win32'",
        ],
    },
    entry_points={"console_scripts": ["swiftscan=swiftscan:main"]},
    python_requires=">=3.11",
)
