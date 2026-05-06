from setuptools import setup, find_packages

setup(
    name="vant-agent",
    version="1.1.0",
    description="VANT-SIEM Endpoint Agent",
    url="https://github.com/leonardovarona42/VANT-SIEM",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "PyYAML>=6.0",
        "requests>=2.28.0",
    ],
    extras_require={
        "tray": ["PyQt6>=6.10; platform_system=='Windows'"],
        "build": ["pyinstaller>=5.0"],
    },
    entry_points={
        "console_scripts": [
            "vant-agent=vant.main:main",
            "vant-agent-tray=vant.tray:main",
        ],
    },
)
