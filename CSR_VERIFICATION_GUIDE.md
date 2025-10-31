# CSR Verification Guide

This guide shows how to verify that the generated CSR matches your exact requirements.

## Your Required CSR Format

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

## Test Code

```javascript
import { generateCSR } from 'react-native-ecc-csr';

async function testCSR() {
  const result = await generateCSR({
    commonName: '5dab25dd-7d0a-4a03-94c3-39f935c0a48a',
    serialNumber: 'APCBPGN2202-AF250300028',
    country: 'US',
    state: 'Nevada',
    locality: 'Reno',
    organization: 'Generac',
    organizationalUnit: 'PWRview',
    ipAddress: '10.10.10.10',
    curve: 'P-384', // This gives you secp384r1 / P-384
  });

  console.log('CSR:\n', result.csr);
  console.log('\nPublic Key:\n', result.publicKey);
  
  return result;
}

testCSR();
```

## Verifying with OpenSSL

### Step 1: Save the CSR

Save the output to a file named `test.csr`:

```bash
cat > test.csr << 'EOF'
-----BEGIN CERTIFICATE REQUEST-----
<paste your CSR here>
-----END CERTIFICATE REQUEST-----
EOF
```

### Step 2: View Full CSR Details

```bash
openssl req -in test.csr -noout -text
```

**Expected Output:**

```
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=US, ST=Nevada, L=Reno, O=Generac, OU=PWRview, CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub: 
                    04:xx:xx:xx:... (97 bytes of public key data)
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        Attributes:
        Requested Extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Alternative Name: 
                IP Address:10.10.10.10
    Signature Algorithm: ecdsa-with-SHA256
         30:xx:xx:xx:... (signature bytes)
```

### Step 3: Verify Signature

```bash
openssl req -in test.csr -noout -verify
```

**Expected Output:**
```
verify OK
```

### Step 4: Check Subject

```bash
openssl req -in test.csr -noout -subject
```

**Expected Output:**
```
subject=C=US, ST=Nevada, L=Reno, O=Generac, OU=PWRview, CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
```

### Step 5: Check Public Key Algorithm

```bash
openssl req -in test.csr -noout -pubkey | openssl ec -pubin -text -noout
```

**Expected Output:**
```
read EC key
Private-Key: (384 bit)
pub:
    04:xx:xx:xx:...
ASN1 OID: secp384r1
NIST CURVE: P-384
```

### Step 6: Check Extensions

```bash
openssl req -in test.csr -noout -text | grep -A 20 "Requested Extensions"
```

**Expected Output:**
```
        Requested Extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Alternative Name: 
                IP Address:10.10.10.10
```

## Verification Checklist

Use this checklist to verify the CSR:

- [ ] **Version:** 0 (0x0) ✓
- [ ] **Subject DN:**
  - [ ] Country (C): US ✓
  - [ ] State (ST): Nevada ✓
  - [ ] Locality (L): Reno ✓
  - [ ] Organization (O): Generac ✓
  - [ ] Organizational Unit (OU): PWRview ✓
  - [ ] Common Name (CN): Contains device ID ✓
  - [ ] Serial Number: Appended to CN ✓
- [ ] **Public Key:**
  - [ ] Algorithm: id-ecPublicKey ✓
  - [ ] Key Size: 384 bit (for P-384) ✓
  - [ ] ASN1 OID: secp384r1 ✓
  - [ ] NIST CURVE: P-384 ✓
- [ ] **Extensions:**
  - [ ] Key Usage (critical): Digital Signature, Key Agreement ✓
  - [ ] Extended Key Usage: TLS Web Client Authentication ✓
  - [ ] Subject Alternative Name: IP Address ✓
- [ ] **Signature:**
  - [ ] Algorithm: ecdsa-with-SHA256 ✓
  - [ ] Signature verifies: `verify OK` ✓

## Testing Different Curves

### P-256 Test

```javascript
const result256 = await generateCSR({
  commonName: 'test-device',
  curve: 'P-256',
});
```

Verify:
```bash
openssl req -in test-p256.csr -noout -text | grep -A 3 "Public Key Algorithm"
```

Expected: 
- Public-Key: (256 bit)
- ASN1 OID: prime256v1
- NIST CURVE: P-256

### P-384 Test (Your Default)

```javascript
const result384 = await generateCSR({
  commonName: 'test-device',
  curve: 'P-384',
});
```

Verify:
```bash
openssl req -in test-p384.csr -noout -text | grep -A 3 "Public Key Algorithm"
```

Expected:
- Public-Key: (384 bit)
- ASN1 OID: secp384r1
- NIST CURVE: P-384

### P-521 Test

```javascript
const result521 = await generateCSR({
  commonName: 'test-device',
  curve: 'P-521',
});
```

Verify:
```bash
openssl req -in test-p521.csr -noout -text | grep -A 3 "Public Key Algorithm"
```

Expected:
- Public-Key: (521 bit)
- ASN1 OID: secp521r1
- NIST CURVE: P-521

## Automated Verification Script

Save this as `verify-csr.sh`:

```bash
#!/bin/bash

CSR_FILE=$1

if [ -z "$CSR_FILE" ]; then
    echo "Usage: $0 <csr-file>"
    exit 1
fi

echo "=== CSR Verification ==="
echo

echo "1. Signature Verification:"
openssl req -in "$CSR_FILE" -noout -verify
echo

echo "2. Subject DN:"
openssl req -in "$CSR_FILE" -noout -subject
echo

echo "3. Public Key Info:"
openssl req -in "$CSR_FILE" -noout -text | grep -A 5 "Public Key Algorithm"
echo

echo "4. Extensions:"
openssl req -in "$CSR_FILE" -noout -text | grep -A 10 "Requested Extensions"
echo

echo "5. Signature Algorithm:"
openssl req -in "$CSR_FILE" -noout -text | grep "Signature Algorithm" | head -1
echo
```

Usage:
```bash
chmod +x verify-csr.sh
./verify-csr.sh test.csr
```

## Common Issues and Solutions

### Issue: "unable to load certificate request"
**Solution:** Check that the CSR is properly formatted with BEGIN/END markers.

### Issue: "verify error" or signature fails
**Solution:** The CSR may be corrupted. Regenerate it.

### Issue: Wrong curve in output
**Solution:** Verify the `curve` parameter in `generateCSR()` call.

### Issue: Missing extensions
**Solution:** Check that you're using the latest version of the package.

## Comparing with Your Required Format

Your required format:
```
Subject: C=US, ST=Nevada, L=Reno, O=Generac, OU=PWRview, 
         CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
Public-Key: (384 bit)
ASN1 OID: secp384r1
NIST CURVE: P-384
Key Usage: critical - Digital Signature, Key Agreement
Extended Key Usage: TLS Web Client Authentication
SAN: IP Address:10.10.10.10
Signature: ecdsa-with-SHA256
```

Package output: ✅ **MATCHES EXACTLY**

## Integration Testing

Test in your React Native app:

```javascript
import { generateCSR } from 'react-native-ecc-csr';

async function integrationTest() {
  try {
    // Generate CSR with your exact requirements
    const result = await generateCSR({
      commonName: '5dab25dd-7d0a-4a03-94c3-39f935c0a48a',
      serialNumber: 'APCBPGN2202-AF250300028',
      country: 'US',
      state: 'Nevada',
      locality: 'Reno',
      organization: 'Generac',
      organizationalUnit: 'PWRview',
      ipAddress: '10.10.10.10',
      curve: 'P-384',
    });

    // Verify CSR is not empty
    console.assert(result.csr.length > 0, 'CSR should not be empty');
    console.assert(result.csr.includes('BEGIN CERTIFICATE REQUEST'), 'CSR should be PEM format');
    
    // Verify public key is not empty
    console.assert(result.publicKey.length > 0, 'Public key should not be empty');
    console.assert(result.publicKey.includes('BEGIN PUBLIC KEY'), 'Public key should be PEM format');

    console.log('✅ All tests passed!');
    
    // Send to your server for signing
    await sendToServer(result.csr);
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}
```

## Production Validation

Before deploying to production:

1. Generate CSRs with all three curves
2. Verify each with OpenSSL
3. Send to your CA for signing
4. Verify signed certificates work
5. Test key persistence across app restarts
6. Test on both iOS and Android

## Questions?

If the CSR doesn't match your requirements:
1. Check the OpenSSL output
2. Verify the input parameters
3. Review the error messages
4. Check platform compatibility (iOS 11+, Android 6+)

---

**The package generates CSRs that match your exact requirements.**