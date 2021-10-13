from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="acmeasync",
    version="0.1.5a",
    description="ACME v2 Client using asyncio",
    author='Greg "GothAck " Miell',
    author_email="acmeasync@greg.gothack.ninja",
    license="MIT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/GothAck/pyacmele",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords="letsencrypt acme proxy",
    python_requires=">=3.7",
    install_requires=["acme", "aiohttp", "aiohttp-requests"],
    entry_points={"console_scripts": ["acmeasyncproxy=acmeasync.__main__:sync_main"]},
)
