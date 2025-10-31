# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-10-30

### Added
- Initial release
- ECC-based CSR generation for React Native
- Support for three ECC curves:
  - P-256 (secp256r1)
  - P-384 (secp384r1)
  - P-521 (secp521r1)
- Customizable subject fields:
  - Common Name (CN)
  - Serial Number
  - Country (C)
  - State/Province (ST)
  - Locality (L)
  - Organization (O)
  - Organizational Unit (OU)
- X509v3 extensions support:
  - Key Usage (critical): Digital Signature, Key Agreement
  - Extended Key Usage: TLS Web Client Authentication
  - Subject Alternative Name: IP Address
- Secure key storage:
  - iOS: iOS Keychain with Secure Enclave support
  - Android: Android KeyStore with hardware-backed keys
- Key management functions:
  - `generateCSR()` - Generate CSR with ECC key pair
  - `getPublicKey()` - Retrieve public key
  - `deleteKeyPair()` - Delete key pair
  - `hasKeyPair()` - Check key pair existence
- iOS native module implementation
- Android native module implementation with BouncyCastle
- TypeScript type definitions
- Comprehensive documentation
- Example React Native app

### Security
- Private keys never leave secure storage
- Hardware-backed key storage when available
- Signature algorithm: ECDSA with SHA-256

### Platform Support
- iOS 11.0 and above
- Android API Level 23 (Android 6.0) and above

## [Unreleased]

### Planned Features
- Support for additional signature algorithms (SHA-384, SHA-512)
- Support for DNS names in Subject Alternative Name
- Support for email addresses in Subject Alternative Name
- Key export functionality (public key only)
- Certificate verification after signing
- PKCS#12 export
- Multiple SAN entries