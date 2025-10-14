from setuptools import setup, find_packages
from build_rust import build_rust_extension, BuildRustExtension

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pqcdualusb",
    version="0.1.0",
    author="Johnson Ajibi",
    author_email="your.email@example.com",
    description="Post-Quantum Cryptography Dual USB Token Library for secure backup operations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/john123304/Post_Quantum_Offline_Manager",
    project_urls={
        "Bug Tracker": "https://github.com/john123304/Post_Quantum_Offline_Manager/issues",
        "Documentation": "https://github.com/john123304/Post_Quantum_Offline_Manager/blob/master/README.md",
        "Source Code": "https://github.com/john123304/Post_Quantum_Offline_Manager",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=3.4.8",
        "psutil>=5.9.0",
        "tqdm>=4.62.0",
        "argon2-cffi>=21.3.0",
    ],
    extras_require={
        "pqc": [
            "oqs-python>=0.5.0",
        ],
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.12.0",
            "black>=21.0.0",
            "isort>=5.9.0",
            "flake8>=3.9.0",
            "mypy>=0.910",
        ],
        "benchmarks": [
            "matplotlib>=3.5.0",
            "numpy>=1.21.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Archiving :: Backup",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="cryptography post-quantum usb backup security token",
    license="MIT",
    ext_modules=build_rust_extension(),
    cmdclass={"build_ext": BuildRustExtension},
    zip_safe=False,  # Required for extensions
)
