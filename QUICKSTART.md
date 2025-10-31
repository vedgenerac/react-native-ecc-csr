# Quick Start Guide

Get up and running with react-native-ecc-csr in 5 minutes!

## 1. Install

```bash
npm install react-native-ecc-csr
cd ios && pod install && cd ..
```

## 2. Import

```javascript
import { generateCSR } from 'react-native-ecc-csr';
```

## 3. Generate Your First CSR

```javascript
async function createCSR() {
  try {
    const result = await generateCSR({
      commonName: 'my-device-id',
      curve: 'P-384', // Choose: 'P-256', 'P-384', or 'P-521'
    });

    console.log('CSR:', result.csr);
    console.log('Public Key:', result.publicKey);
  } catch (error) {
    console.error('Error:', error.message);
  }
}

createCSR();
```

## 4. Complete Example with All Fields

```javascript
const result = await generateCSR({
  // Required
  commonName: '5dab25dd-7d0a-4a03-94c3-39f935c0a48a',
  
  // Optional - Subject Information
  serialNumber: 'APCBPGN2202-AF250300028',
  country: 'US',
  state: 'Nevada',
  locality: 'Reno',
  organization: 'Generac',
  organizationalUnit: 'PWRview',
  
  // Optional - Extensions
  ipAddress: '10.10.10.10',
  
  // Optional - Configuration
  curve: 'P-384', // or 'P-256', 'P-521'
  keyAlias: 'MY_DEVICE_KEY', // for key storage
});
```

## 5. Verify Your CSR

Save the CSR to a file and verify with OpenSSL:

```bash
# Save CSR
echo "-----BEGIN CERTIFICATE REQUEST-----
...your CSR content...
-----END CERTIFICATE REQUEST-----" > my-csr.pem

# View details
openssl req -in my-csr.pem -noout -text

# Verify signature
openssl req -in my-csr.pem -noout -verify
```

## 6. Key Management

```javascript
// Check if key exists
const exists = await hasKeyPair('MY_KEY');

// Get public key
if (exists) {
  const publicKey = await getPublicKey('MY_KEY');
  console.log(publicKey);
}

// Delete key when done
await deleteKeyPair('MY_KEY');
```

## Common Use Cases

### IoT Device Registration

```javascript
const deviceCSR = await generateCSR({
  commonName: deviceId,
  serialNumber: serialNumber,
  organization: 'MyIoTCompany',
  curve: 'P-384',
});

// Send deviceCSR.csr to your server for signing
```

### Mobile Client Authentication

```javascript
const clientCSR = await generateCSR({
  commonName: userId,
  organization: 'MyApp',
  organizationalUnit: 'Mobile',
  curve: 'P-256', // Faster for mobile
});
```

### High-Security Applications

```javascript
const secureCSR = await generateCSR({
  commonName: systemId,
  organization: 'SecureOrg',
  curve: 'P-521', // Maximum security
});
```

## Next Steps

- 📖 Read the full [README.md](README.md) for detailed API documentation
- 💻 Check out the [example/App.js](example/App.js) for a complete working app
- 🔧 See [INSTALLATION.md](INSTALLATION.md) for troubleshooting

## Quick Reference

### ECC Curves

| Curve | Security | Speed | Use Case |
|-------|----------|-------|----------|
| P-256 | Good | Fast | Mobile apps, IoT |
| P-384 | High | Medium | Recommended default |
| P-521 | Maximum | Slower | Critical systems |

### Output Format

The CSR includes:
- ✅ Subject DN with all provided fields
- ✅ ECC Public Key (256/384/521 bit)
- ✅ Key Usage: Digital Signature, Key Agreement
- ✅ Extended Key Usage: TLS Client Auth
- ✅ Subject Alternative Name: IP Address
- ✅ Signature: ECDSA-SHA256

### Platform Support

- iOS 11.0+
- Android API 23+ (Android 6.0+)
- React Native 0.60+

## Need Help?

- 🐛 [Report Issues](https://github.com/yourusername/react-native-ecc-csr/issues)
- 💬 [Discussions](https://github.com/yourusername/react-native-ecc-csr/discussions)
- 📧 Contact: your.email@example.com