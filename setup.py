"""Setup for AI Security Pipeline."""

from setuptools import setup, find_packages

setup(
    name="ai-security-pipeline",
    version="0.1.0",
    description="Unified AI Security Framework",
    author="Cybathreat",
    author_email="ahmed.chiboub@cybacrest.com",
    url="https://github.com/cybathreat/ai-security-pipeline",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "jinja2>=3.1.0",
        "click>=8.0.0",
        "colorama>=0.4.4",
        "tabulate>=0.8.9",
        "packaging>=21.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.6.0",
            "pylint>=2.15.0",
            "mypy>=1.0.0",
        ],
        "sarif": ["sarif-om>=1.0.4"],
    },
    entry_points={
        "console_scripts": [
            "ai-security-pipeline=ai_security_pipeline.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
