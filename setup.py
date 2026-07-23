from setuptools import setup, find_packages

setup(
    name="iam-simulator",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["click>=8.1"],
    entry_points={
        "console_scripts": [
            "iam=iam_simulator.cli:main",
        ],
    },
    python_requires=">=3.10",
)
