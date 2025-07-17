#!/usr/bin/env python3
"""
Setup script for MCP Security Platform Plugin SDK
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mcp-plugin-sdk",
    version="1.0.0",
    author="MCP Security Platform Team",
    author_email="platform@mcp-security.com",
    description="Plugin SDK for MCP Security Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mcp-security/platform",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        "pydantic>=2.0.0",
        "redis>=5.0.0",
        "pyyaml>=6.0.0",
        "aiohttp>=3.8.0",
        "asyncio-mqtt>=0.13.0",
        "structlog>=23.0.0",
        "jsonschema>=4.0.0",
        "typing-extensions>=4.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.10.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
        "wasm": [
            "wasmtime>=14.0.0",
            "wasmer>=1.1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "mcp-plugin=mcp_plugin_sdk.cli:main",
        ],
    },
)