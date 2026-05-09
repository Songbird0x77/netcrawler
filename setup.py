from setuptools import setup, find_packages

setup(
    name="netcrawler",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["rich", "typer"],
    entry_points={
        "console_scripts": [
            "netcrawler=netcrawler_cli:app",
        ],
    },
)
