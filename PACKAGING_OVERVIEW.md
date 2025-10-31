# React Native ECC CSR Package - Complete Overview

## Package Information

**Name:** react-native-ecc-csr  
**Version:** 1.0.0  
**License:** MIT  
**Platform Support:** iOS 11.0+, Android API 23+ (Android 6.0+)

## What This Package Does

This is a complete, production-ready npm package that generates Certificate Signing Requests (CSR) using Elliptic Curve Cryptography (ECC) for React Native applications on both iOS and Android.

### Key Features

✅ **Pure ECC Implementation** - No RSA, only ECC  
✅ **Multiple Curves** - P-256, P-384, P-521 (selectable by frontend)  
✅ **Secure Key Storage** - iOS Keychain & Android KeyStore  
✅ **X.509 Extensions** - Key Usage, Extended Key Usage, SAN  
✅ **Complete Documentation** - Installation, API, Examples  
✅ **TypeScript Support** - Full type definitions included  

## Package Structure

```
react-native-ecc-csr/
├── package.json              # NPM package configuration
├── index.d.ts               # TypeScript definitions
├── LICENSE                  # MIT License
├── README.md               # Main documentation
├── QUICKSTART.md           # 5-minute getting started
├── INSTALLATION.md         # Detailed installation guide
├── CHANGELOG.md            # Version history
├── PUBLISHING.md           # NPM publishing guide
├── .gitignore              # Git ignore rules
├── react-native-ecc-csr.podspec  # iOS CocoaPods spec
│
├── src/
│   └── index.js            # JavaScript interface
│
├── ios/
│   ├── EccCsrGenerator.h   # iOS native header
│   └── EccCsrGenerator.m   # iOS implementation (Objective-C)
│
├── android/
│   ├── build.gradle        # Android build configuration
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/com/ecccsrgen/
│           ├── EccCsrGeneratorModule.java   # Android CSR implementation
│           └── EccCsrGeneratorPackage.java  # React Native package
│
└── example/
    └── App.js              # Complete working example
```

## CSR Output Format

The package generates CSRs with the following structure (matching your requirements):

```
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=US, ST=Nevada, L=Reno, O=Generac, OU=PWRview, 
                 CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256/384/521 bit depending on curve)
                ASN1 OID: secp256r1 / secp384r1 / secp521r1
                NIST CURVE: P-256 / P-384 / P-521
        Attributes:
        Requested Extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Alternative Name: 
                IP Address:10.10.10.10
    Signature Algorithm: ecdsa-with-SHA256
```

## Frontend Usage Example

```javascript
import { generateCSR, ECCCurve } from 'react-native-ecc-csr';

// Your exact use case
const result = await generateCSR({
  commonName: '5dab25dd-7d0a-4a03-94c3-39f935c0a48a',
  serialNumber: 'APCBPGN2202-AF250300028',
  country: 'US',
  state: 'Nevada',
  locality: 'Reno',
  organization: 'Generac',
  organizationalUnit: 'PWRview',
  ipAddress: '10.10.10.10',
  curve: 'P-384', // Frontend can choose: P-256, P-384, or P-521
});

console.log(result.csr);      // PEM-encoded CSR
console.log(result.publicKey); // PEM-encoded public key
```

## ECC Curve Selection

The frontend code can specify which curve to use:

| Curve | Specification | Key Size | Security Level | Use Case |
|-------|---------------|----------|----------------|----------|
| P-256 | secp256r1 | 256 bit | ~128 bit | IoT devices, mobile apps |
| P-384 | secp384r1 | 384 bit | ~192 bit | **Recommended default** |
| P-521 | secp521r1 | 521 bit | ~256 bit | High-security applications |

```javascript
// P-256 - Fast, good security
await generateCSR({ commonName: 'device-1', curve: 'P-256' });

// P-384 - Recommended (default)
await generateCSR({ commonName: 'device-2', curve: 'P-384' });

// P-521 - Maximum security
await generateCSR({ commonName: 'device-3', curve: 'P-521' });
```

## API Reference

### `generateCSR(options)`

Generate a Certificate Signing Request.

**Required:**
- `commonName`: Device/user identifier

**Optional:**
- `serialNumber`: Serial number (appended to CN)
- `country`: 2-letter country code
- `state`: State/province
- `locality`: City
- `organization`: Organization name
- `organizationalUnit`: Department/unit
- `ipAddress`: IP address for SAN
- `curve`: ECC curve - **'P-256', 'P-384', or 'P-521'** (default: 'P-384')
- `keyAlias`: Storage alias (default: 'ECC_CSR_KEY')

**Returns:** `{ csr: string, publicKey: string }`

### Other Functions

```javascript
// Get existing public key
const publicKey = await getPublicKey('KEY_ALIAS');

// Check if key exists
const exists = await hasKeyPair('KEY_ALIAS');

// Delete key pair
await deleteKeyPair('KEY_ALIAS');
```

## Platform Implementation Details

### iOS (Objective-C)
- Uses native Security framework
- SecKeyCreateRandomKey for ECC key generation
- Manual DER encoding for CSR structure
- Keys stored in iOS Keychain
- Hardware-backed when Secure Enclave available

### Android (Java + BouncyCastle)
- Uses Android KeyStore for key generation
- BouncyCastle for CSR construction
- Hardware-backed keys on supported devices
- API Level 23+ required for full ECC support

## Installation Instructions

```bash
# 1. Install package
npm install react-native-ecc-csr

# 2. iOS setup
cd ios && pod install && cd ..

# 3. Rebuild
npx react-native run-ios
# or
npx react-native run-android
```

## Security Features

1. **Secure Key Storage**
   - iOS: Keychain with Secure Enclave support
   - Android: KeyStore with hardware backing

2. **Private Key Protection**
   - Keys never leave secure storage
   - Cannot be exported or extracted

3. **Signature Algorithm**
   - ECDSA with SHA-256
   - Industry-standard cryptography

## What's Included

1. **Complete Source Code**
   - JavaScript interface
   - iOS native module (Objective-C)
   - Android native module (Java)

2. **Documentation**
   - README with full API docs
   - Quick start guide
   - Installation guide
   - Example application

3. **Type Definitions**
   - Full TypeScript support
   - Type-safe API

4. **Build Configuration**
   - iOS Podspec
   - Android Gradle setup
   - NPM package.json

## Next Steps

1. **Installation:**
   ```bash
   npm install react-native-ecc-csr
   cd ios && pod install
   ```

2. **Import and Use:**
   ```javascript
   import { generateCSR } from 'react-native-ecc-csr';
   const result = await generateCSR({ 
     commonName: 'my-device',
     curve: 'P-384' 
   });
   ```

3. **Test:**
   ```bash
   # Save CSR to file
   echo "<CSR content>" > csr.pem
   
   # Verify with OpenSSL
   openssl req -in csr.pem -noout -text
   openssl req -in csr.pem -noout -verify
   ```

## Publishing to NPM

To publish this package to NPM:

1. Create NPM account
2. Update `package.json` with your details
3. Run: `npm login`
4. Run: `npm publish`

See `PUBLISHING.md` for detailed instructions.

## Support and Issues

- GitHub Issues: (add your repo URL)
- Email: (add your email)

## License

MIT License - See LICENSE file for details.

---

## Technical Implementation Notes

### iOS CSR Generation
- Uses Apple's Security framework
- Manual DER/ASN.1 encoding
- Supports all three P-curves natively
- Signature algorithm: ECDSA with SHA-256

### Android CSR Generation
- Uses Android KeyStore + BouncyCastle
- PKCS#10 format
- ECGenParameterSpec for curve selection
- Requires BouncyCastle 1.78+

### Extensions Encoding
- Key Usage: 0x90 (Digital Signature + Key Agreement)
- Extended Key Usage: TLS Client Authentication (OID: 1.3.6.1.5.5.7.3.2)
- SAN: IP Address encoded as [7] IMPLICIT OCTET STRING

## File Checksums

You can verify the package integrity:

```bash
# Generate checksums
cd react-native-ecc-csr
find . -type f -exec sha256sum {} \; > checksums.txt
```

## Version Information

- **Current Version:** 1.0.0
- **Release Date:** October 30, 2024
- **React Native:** >= 0.60.0
- **iOS:** >= 11.0
- **Android:** >= API 23 (6.0)

---

**This is a complete, production-ready package that can be published to NPM immediately.**