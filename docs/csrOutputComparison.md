# CSR Output Comparison

## Your Desired Output (What you wanted)

```
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=US, ST=Nevada, L=Reno, O=Generac, OU=PWRview, CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub: 
                    04:1d:79:5e:f8:33:cd:1c:f5:fd:d2:47:e0:46:b9:
                    f2:15:28:b2:01:29:ec:90:00:28:dd:70:a1:b0:58:
                    b9:32:51:d4:01:71:bf:4c:0f:5f:ad:24:88:fc:84:
                    85:86:d2:a6:15:61:68:ca:7f:51:eb:95:36:49:ed:
                    83:42:a7:ea:ad:ee:32:cd:d4:20:c0:a9:bb:df:a8:
                    bb:5f:f9:88:d2:10:3f:4d:d6:7e:8a:dd:cf:5c:6b:
                    b7:15:6c:16:69:a8:39
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        Attributes:
        Requested Extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Alternative Name:              ← THIS WAS MISSING!
                IP Address:10.10.10.10                    ← THIS WAS MISSING!
    Signature Algorithm: ecdsa-with-SHA256                ← THIS WAS SHA384!
         30:65:02:30:13:5d:e5:11:5c:16:69:32:c5:68:63:38:0d:ac:
         dd:40:c5:dc:f4:15:ff:82:18:2b:6a:47:8e:51:fa:6e:96:bc:
         3d:4b:cb:2a:39:09:3c:95:78:49:ab:56:5f:31:ea:43:02:31:
         00:f2:db:ac:95:24:6b:f2:04:47:2c:0e:7c:73:ba:bb:66:0c:
         0d:39:91:6a:15:5a:20:6c:99:70:ea:d3:7f:6d:f2:e4:50:5e:
         15:11:d1:fe:f6:19:a3:f2:d2:6f:4b:49:2e
```

## What Your Old Code Was Producing

```
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=US, ST=Wisconsin, L=Waukesha, O=Generac Power Systems, Inc, OU=PWRview, CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub: 
                    04:26:b2:eb:fc:6d:fe:92:03:32:ba:f6:89:6f:ef:
                    22:a0:81:f5:26:f7:1f:18:45:c8:1a:36:b5:f9:df:
                    c3:05:23:c2:3a:73:48:7b:3e:e9:0b:08:f2:9c:3d:
                    a2:74:23:f2:d7:61:5e:0d:23:7d:b6:a2:15:99:76:
                    14:79:6d:18:2b:b0:b7:33:94:38:f6:eb:f6:3a:51:
                    1a:41:14:87:98:c6:69:08:26:3c:c0:5a:75:1f:a9:
                    e3:2e:d6:6d:fb:45:f8
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        Attributes:
        Requested Extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            ❌ NO SUBJECT ALTERNATIVE NAME!
    Signature Algorithm: ecdsa-with-SHA384  ❌ WRONG! Should be SHA256
         30:66:02:31:00:fa:f4:56:47:14:67:00:72:8e:58:e6:35:eb:
         86:11:3c:5e:72:1a:b9:c7:98:72:cc:ec:22:68:ee:b6:3c:08:
         20:bb:00:42:9b:52:85:6d:c2:6f:68:01:a3:55:f9:e7:7e:02:
         31:00:b7:75:77:62:45:5a:03:a5:f5:c8:a1:de:14:81:9b:45:
         ae:6b:3d:9c:60:05:73:c8:c8:63:0c:a7:bb:8d:d9:41:3d:20:
         01:26:5d:03:db:55:cb:4b:55:63:1a:28:6d:6c
```

## What the New Code Produces ✅

```
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=US, ST=Nevada, L=Reno, O=Generac, OU=PWRview, CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)  ✅ Configurable: 256, 384, or 521 bit
                pub: 
                    [random public key bytes - will differ each time]
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        Attributes:
        Requested Extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Alternative Name:  ✅ NOW INCLUDED!
                IP Address:10.10.10.10         ✅ CONFIGURABLE!
    Signature Algorithm: ecdsa-with-SHA256    ✅ CORRECT!
         [signature bytes will differ each time]
```

## Side-by-Side Key Differences

| Feature | Old Code ❌ | New Code ✅ |
|---------|-----------|-----------|
| Signature Algorithm | SHA384 | **SHA256** |
| Subject Alternative Name | Missing | **IP Address included** |
| Curve Selection | Hardcoded P-384 | **Configurable (P-256/P-384/P-521)** |
| API Design | Individual params | **Params object** |
| TypeScript Support | Limited/None | **Full type safety** |
| IP Address | Not configurable | **Configurable (default: 10.10.10.10)** |

## Testing Your CSR

### Step 1: Generate CSR
```typescript
const result = await CSRModule.generateCSR({
  country: "US",
  state: "Nevada",
  locality: "Reno",
  organization: "Generac",
  organizationalUnit: "PWRview",
  commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
  serialNumber: "APCBPGN2202-AF250300028",
  ipAddress: "10.10.10.10",
  curve: "secp384r1"
});

// Save to file
await fs.writeFile('csr.csr', result.csr);
```

### Step 2: Verify with OpenSSL
```bash
openssl req -in csr.csr -noout -text
```

### Step 3: Check Critical Fields
```bash
# Should show: ecdsa-with-SHA256
openssl req -in csr.csr -noout -text | grep "Signature Algorithm"

# Should show: Public-Key: (384 bit)
openssl req -in csr.csr -noout -text | grep "Public-Key"

# Should show: IP Address:10.10.10.10
openssl req -in csr.csr -noout -text | grep -A 1 "Subject Alternative Name"
```

## Expected Output After Fix

All three commands should show:
```
✅ Signature Algorithm: ecdsa-with-SHA256
✅ Public-Key: (384 bit)
✅ X509v3 Subject Alternative Name:
       IP Address:10.10.10.10
```

## Different Curves Comparison

### P-256 Output
```
Public-Key: (256 bit)
ASN1 OID: prime256v1
NIST CURVE: P-256
```

### P-384 Output (Your Requirement)
```
Public-Key: (384 bit)
ASN1 OID: secp384r1
NIST CURVE: P-384
```

### P-521 Output
```
Public-Key: (521 bit)
ASN1 OID: secp521r1
NIST CURVE: P-521
```

## Common Mistakes to Avoid

❌ **Don't do this:**
```typescript
// Old way - won't work with new code
await CSRModule.generateCSR("US", "Nevada", "Reno", ...);
```

✅ **Do this:**
```typescript
// New way - params object
await CSRModule.generateCSR({
  country: "US",
  state: "Nevada",
  locality: "Reno",
  // ... other params
});
```

## Validation Checklist

Before using in production, verify:
- [ ] Signature Algorithm is `ecdsa-with-SHA256` (not SHA384)
- [ ] Subject Alternative Name includes IP address
- [ ] Correct curve is being used (P-384 for your case)
- [ ] All subject DN fields are correct
- [ ] Key Usage extensions are present
- [ ] Extended Key Usage shows "TLS Web Client Authentication"

## Success Criteria

Your CSR is correct if OpenSSL shows:
1. ✅ `Signature Algorithm: ecdsa-with-SHA256`
2. ✅ `Public-Key: (384 bit)` with `NIST CURVE: P-384`
3. ✅ `X509v3 Subject Alternative Name: IP Address:10.10.10.10`
4. ✅ `X509v3 Key Usage: critical` with `Digital Signature, Key Agreement`
5. ✅ `X509v3 Extended Key Usage:` with `TLS Web Client Authentication`

All five must be present for the CSR to match your requirements!