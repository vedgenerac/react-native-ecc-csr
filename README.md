# React Native ECC CSR Module

A React Native module for generating Certificate Signing Requests (CSR) with Elliptic Curve Cryptography (ECC) support.

## Features

- ✅ Generate CSR with ECC keys (P-256, P-384, P-521)
- ✅ SHA256 signature algorithm
- ✅ Subject Alternative Name (SAN) support with IP addresses
- ✅ Full TypeScript support
- ✅ Configurable subject DN fields
- ✅ Key Usage and Extended Key Usage extensions
- ✅ Standards-compliant PKCS#10 format

## Installation

```bash
npm install react-native-ecc-csr
# or
yarn add react-native-ecc-csr
```

## Quick Start

```typescript
import CSRModule from 'react-native-ecc-csr';

const params = {
  country: "US",
  state: "Nevada",
  locality: "Reno",
  organization: "Generac",
  organizationalUnit: "PWRview",
  commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
  serialNumber: "APCBPGN2202-AF250300028",
  ipAddress: "10.10.10.10",
  curve: "secp384r1" // Optional: defaults to P-384
};

const result = await CSRModule.generateCSR(params);
console.log(result.csr);        // PEM-encoded CSR
console.log(result.privateKey); // PEM-encoded private key
console.log(result.publicKey);  // Base64-encoded public key
```

## API Reference

### `generateCSR(params: CSRParams): Promise<CSRResult>`

Generates a Certificate Signing Request with the specified parameters.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `commonName` | string | Yes | - | Common Name (CN) for the certificate |
| `country` | string | No | "US" | Country code (C) |
| `state` | string | No | "Nevada" | State or province (ST) |
| `locality` | string | No | "Reno" | Locality or city (L) |
| `organization` | string | No | "Generac" | Organization name (O) |
| `organizationalUnit` | string | No | "PWRview" | Organizational unit (OU) |
| `serialNumber` | string | No | "" | Serial number |
| `ipAddress` | string | No | "10.10.10.10" | IP address for SAN extension |
| `curve` | ECCurve | No | "secp384r1" | ECC curve: "secp256r1", "secp384r1", or "secp521r1" |

#### Returns

```typescript
{
  csr: string;        // PEM-encoded CSR
  privateKey: string; // PEM-encoded private key
  publicKey: string;  // Base64-encoded public key
}
```

### `generateKeyPair(params: KeyPairParams): Promise<KeyPairResult>`

Generates an ECC key pair.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `curve` | ECCurve | No | "secp384r1" | ECC curve to use |

#### Returns

```typescript
{
  privateKey: string; // PEM-encoded private key
  publicKey: string;  // Base64-encoded public key
}
```

## Supported Curves

| Curve | Key Size | Security Level | Best For |
|-------|----------|----------------|----------|
| `secp256r1` (P-256) | 256 bits | ~128-bit | IoT devices, performance-critical |
| `secp384r1` (P-384) | 384 bits | ~192-bit | Enterprise, general use (default) |
| `secp521r1` (P-521) | 521 bits | ~256-bit | Maximum security, long-term |

See [CURVE_SELECTION_GUIDE.md](./CURVE_SELECTION_GUIDE.md) for detailed curve comparison.

## Examples

### Minimal CSR (with defaults)

```typescript
const result = await CSRModule.generateCSR({
  commonName: "device-12345"
});
```

### CSR with P-256 curve

```typescript
const result = await CSRModule.generateCSR({
  commonName: "iot-device-001",
  curve: "secp256r1",
  ipAddress: "192.168.1.100"
});
```

### CSR with maximum security (P-521)

```typescript
const result = await CSRModule.generateCSR({
  country: "US",
  organization: "High Security Corp",
  commonName: "secure-device",
  curve: "secp521r1"
});
```

### Generate key pair only

```typescript
const keyPair = await CSRModule.generateKeyPair({
  curve: "secp384r1"
});
```

See [example-usage.tsx](./example-usage.tsx) for more examples.

## Verify Generated CSR

```bash
# View CSR details
openssl req -in csr.csr -noout -text

# Check signature algorithm (should be ecdsa-with-SHA256)
openssl req -in csr.csr -noout -text | grep "Signature Algorithm"

# Check curve
openssl req -in csr.csr -noout -text | grep -A 2 "Public-Key"

# Check SAN
openssl req -in csr.csr -noout -text | grep -A 1 "Subject Alternative Name"
```

## Generated CSR Format

The module generates CSRs with the following characteristics:

- **Format:** PKCS#10
- **Signature Algorithm:** ecdsa-with-SHA256
- **Key Usage (critical):** Digital Signature, Key Agreement
- **Extended Key Usage:** TLS Web Client Authentication
- **Subject Alternative Name:** IP Address (configurable)

Example output:
```
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=US, ST=Nevada, L=Reno, O=Generac, OU=PWRview, CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        Requested Extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Alternative Name: 
                IP Address:10.10.10.10
    Signature Algorithm: ecdsa-with-SHA256
```

## TypeScript Support

Full TypeScript definitions are included:

```typescript
import CSRModule, { 
  CSRParams, 
  CSRResult, 
  ECCurve,
  KeyPairParams,
  KeyPairResult 
} from 'react-native-ecc-csr';

const params: CSRParams = {
  commonName: "device-001",
  curve: "secp384r1"
};

const result: CSRResult = await CSRModule.generateCSR(params);
```

## Migration from Previous Versions

If you're upgrading from a version that used individual parameters, see [MIGRATION_GUIDE.md](./MIGRATION_GUIDE.md).

**Key changes:**
- ✅ Parameters now passed as object instead of individual arguments
- ✅ Signature algorithm changed from SHA384 to SHA256
- ✅ Added SAN IP address extension
- ✅ Added curve selection support

## Documentation

- [Migration Guide](./MIGRATION_GUIDE.md) - Upgrading from older versions
- [Curve Selection Guide](./CURVE_SELECTION_GUIDE.md) - Choosing the right ECC curve
- [Example Usage](./example-usage.tsx) - Complete code examples

## Requirements

- React Native >= 0.60
- Android SDK >= 21
- BouncyCastle library (included)

## Dependencies

### Android
- `org.bouncycastle:bcprov-jdk15on:1.70` (or compatible version)
- `org.bouncycastle:bcpkix-jdk15on:1.70` (or compatible version)

## License

[Your License Here]

## Contributing

[Your Contributing Guidelines]

## Support

For issues and questions:
- GitHub Issues: [your-repo-url]
- Documentation: [your-docs-url]