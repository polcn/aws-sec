from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aws-security-tool",
    version="1.0.0",
    author="AWS Security Tool Team",
    description="Comprehensive AWS security analysis tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/aws-security-tool",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.9",
    install_requires=[
        "boto3>=1.34.0",
        "botocore>=1.34.0",
        "jinja2>=3.1.2",
        "python-dateutil>=2.8.2",
        "typing-extensions>=4.8.0",
        "pydantic>=2.5.0",
        "rich>=13.7.0",
        "click>=8.1.7",
        "PyYAML>=6.0.1",
        "cryptography>=41.0.7",
        "markdown>=3.5.1",
    ],
    entry_points={
        "console_scripts": [
            "aws-security-tool=src.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["templates/*.html", "templates/*.md"],
    },
)