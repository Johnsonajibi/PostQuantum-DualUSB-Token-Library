## PostQuantum DualUSB Token Library v0.1.0

We're excited to announce the first official release of PostQuantum DualUSB Token Library - a Python package that brings enterprise-grade security to dual USB backup systems with future-proof cryptography.

### What makes this special?

In an era where quantum computers threaten traditional encryption, this library provides a practical solution for securing sensitive data across two USB devices. Whether you're protecting cryptocurrency keys, enterprise secrets, or personal data, this release gives you military-grade security that's ready for the quantum age.

### Key capabilities in this release

**Quantum-resistant protection**
- Post-quantum digital signatures using the Dilithium algorithm
- AES-256-GCM encryption with authenticated data
- Memory-hard key derivation using Argon2id
- Cryptographic audit trails with HMAC-SHA256

**Dual USB security model**
- Secrets split across two physical devices for redundancy
- No single point of failure - losing one USB doesn't compromise security
- Hardware binding prevents device cloning attacks
- Tamper-evident logging tracks all operations

**Production-ready features**
- Secure memory management with automatic cleanup
- Protection against timing-based attacks
- Works reliably on Windows, Linux, and macOS
- Real-time progress monitoring for long operations

### Getting started

Installing and using the library is straightforward:

```bash
# Install from PyPI
pip install pqcdualusb

# Set up your dual USB configuration
pqcdualusb init --primary /media/usb1 --secondary /media/usb2

# Create an encrypted backup
pqcdualusb backup --data "sensitive.json" --passphrase "your-secure-passphrase"
```

### Who should use this?

This library is designed for anyone who needs serious security:

- **Developers** building offline password managers or key storage systems
- **Organizations** requiring air-gapped security for sensitive operations  
- **Cryptocurrency users** who want hardware-level protection for wallet keys
- **Security professionals** implementing enterprise key custody solutions
- **Privacy-conscious individuals** who want quantum-proof personal data protection

### Performance you can count on

We've optimized the library for real-world usage:

- USB device detection completes in under 1 second
- Token creation takes less than 5 seconds
- Backup and restore operations finish in 1-10 seconds
- Memory usage stays under 100MB even for large operations

### What's coming next

This initial release establishes the foundation. Future versions will include:

- Enhanced documentation with step-by-step tutorials
- Additional post-quantum cryptographic algorithms
- Performance optimizations for large-scale deployments
- Extended platform support and testing

### Resources

- **Installation guide**: [PyPI package](https://pypi.org/project/pqcdualusb/)
- **Usage examples**: Check the README.md in this repository
- **Security details**: Review our SECURITY.md policy
- **Contributing**: See CONTRIBUTING.md for development guidelines

### Support the project

If this library helps secure your projects, consider:
- Starring the repository to increase visibility
- Sharing with colleagues who work with sensitive data
- Contributing improvements or reporting issues
- Providing feedback on your use cases

Thank you for trusting PostQuantum DualUSB Token Library with your security needs. We're committed to providing reliable, quantum-resistant protection for your most valuable data.
