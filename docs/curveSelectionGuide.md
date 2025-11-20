# ECC Curve Selection Guide

## Supported Curves

The CSR module supports three NIST-standardized elliptic curves:

### 1. secp256r1 (P-256)
- **Key Size:** 256 bits
- **Also Known As:** prime256v1, NIST P-256
- **Security Level:** ~128-bit equivalent security
- **Performance:** Fastest
- **Use Cases:**
  - IoT devices with limited processing power
  - High-frequency operations
  - Mobile devices where battery life matters
  - TLS/SSL connections (widely supported)

**Example:**
```typescript
const params: CSRParams = {
  commonName: "iot-device-001",
  curve: "secp256r1"
};
```

### 2. secp384r1 (P-384) - **DEFAULT**
- **Key Size:** 384 bits
- **Also Known As:** NIST P-384
- **Security Level:** ~192-bit equivalent security
- **Performance:** Moderate
- **Use Cases:**
  - General-purpose enterprise applications
  - Government/military applications (Suite B)
  - Long-term certificate validity (5-10 years)
  - **Your requirement** (Generac PWRview devices)

**Example:**
```typescript
const params: CSRParams = {
  commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
  serialNumber: "APCBPGN2202-AF250300028",
  curve: "secp384r1" // or omit (default)
};
```

### 3. secp521r1 (P-521)
- **Key Size:** 521 bits (not 512!)
- **Also Known As:** NIST P-521
- **Security Level:** ~256-bit equivalent security
- **Performance:** Slowest
- **Use Cases:**
  - Maximum security requirements
  - Top Secret government communications
  - Long-term (20+ years) security needs
  - Financial institutions with extreme security requirements

**Example:**
```typescript
const params: CSRParams = {
  commonName: "high-security-vault",
  curve: "secp521r1"
};
```

## Comparison Table

| Curve | Key Size | Security Level | Speed | Certificate Size | Signature Size |
|-------|----------|----------------|-------|------------------|----------------|
| P-256 | 256 bits | 128-bit equiv. | Fast  | Smallest (~320 bytes) | Smallest (~64 bytes) |
| P-384 | 384 bits | 192-bit equiv. | Medium | Medium (~384 bytes) | Medium (~96 bytes) |
| P-521 | 521 bits | 256-bit equiv. | Slow | Largest (~521 bytes) | Largest (~132 bytes) |

## Security Recommendations

### Current (2025) Recommendations:
- **P-256**: Secure until ~2030
- **P-384**: Secure until ~2050+ (NSA Suite B approved)
- **P-521**: Secure for foreseeable future (>2050)

### When to Use Each:

**Use P-256 if:**
- You need maximum performance
- Certificate validity is ≤5 years
- Compatibility with older systems is crucial
- IoT/embedded devices with limited resources

**Use P-384 if:** (Recommended for most cases)
- You want a good balance of security and performance
- Certificate validity is 5-10 years
- Government/enterprise compliance requirements
- This is the default and matches your original requirement

**Use P-521 if:**
- Maximum security is paramount
- Certificate validity is >10 years
- Performance is not a critical concern
- Top Secret or classified information handling

## Performance Considerations

Approximate operations per second (on modern mobile processors):

| Operation | P-256 | P-384 | P-521 |
|-----------|-------|-------|-------|
| Key Generation | ~500/sec | ~200/sec | ~100/sec |
| Signing | ~1000/sec | ~400/sec | ~200/sec |
| Verification | ~400/sec | ~150/sec | ~80/sec |

## Compatibility Notes

### Excellent Compatibility (>99% systems):
- P-256: Universal support across all modern systems
- P-384: Excellent support, required for NSA Suite B

### Good Compatibility (~95% systems):
- P-521: Well supported, but some older systems may not support it

## Your Original Requirement

Based on your desired CSR output, you should use:

```typescript
const params: CSRParams = {
  country: "US",
  state: "Nevada",
  locality: "Reno",
  organization: "Generac",
  organizationalUnit: "PWRview",
  commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
  serialNumber: "APCBPGN2202-AF250300028",
  ipAddress: "10.10.10.10",
  curve: "secp384r1" // P-384 (matches your requirement)
};
```

This produces:
```
Public-Key: (384 bit)
ASN1 OID: secp384r1
NIST CURVE: P-384
```

## Code Examples

### Generate CSR with each curve:

```typescript
// P-256 (fast, good for IoT)
const p256Result = await CSRModule.generateCSR({
  commonName: "device-001",
  curve: "secp256r1"
});

// P-384 (balanced, default)
const p384Result = await CSRModule.generateCSR({
  commonName: "device-002",
  curve: "secp384r1" // or omit for default
});

// P-521 (maximum security)
const p521Result = await CSRModule.generateCSR({
  commonName: "device-003",
  curve: "secp521r1"
});
```

## Validation

To verify your curve in the generated CSR:

```bash
# Check the curve in CSR
openssl req -in csr.csr -noout -text | grep -A 2 "Public-Key"
```

Expected output:
```
Public-Key: (256 bit)   # for P-256
Public-Key: (384 bit)   # for P-384
Public-Key: (521 bit)   # for P-521

ASN1 OID: secp256r1     # or secp384r1 or secp521r1
NIST CURVE: P-256       # or P-384 or P-521
```

## References

- [NIST FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final) - Digital Signature Standard
- [NSA Suite B Cryptography](https://en.wikipedia.org/wiki/NSA_Suite_B_Cryptography)
- [RFC 5480](https://tools.ietf.org/html/rfc5480) - Elliptic Curve Cryptography Subject Public Key Information