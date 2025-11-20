# Migration Guide: Updated CSR Module

## What Changed

### 1. Java Method Signature (CSRModule.java)

**OLD (Individual parameters):**
```java
@ReactMethod
public void generateCSR(
    String country,
    String state,
    String locality,
    // ... many individual parameters
    Promise promise
)
```

**NEW (Single params object):**
```java
@ReactMethod
public void generateCSR(ReadableMap params, Promise promise)
```

### 2. TypeScript Interface (index.ts)

**OLD:**
```typescript
// Likely had individual parameters or no types
generateCSR(
  country: string,
  state: string,
  locality: string,
  // ... etc
): Promise<CSRResult>
```

**NEW:**
```typescript
generateCSR(params: CSRParams): Promise<CSRResult>
```

### 3. Usage Pattern

**OLD:**
```typescript
await CSRModule.generateCSR(
  "US",
  "Nevada", 
  "Reno",
  "Generac",
  "PWRview",
  "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
  "APCBPGN2202-AF250300028"
);
```

**NEW:**
```typescript
await CSRModule.generateCSR({
  country: "US",
  state: "Nevada",
  locality: "Reno",
  organization: "Generac",
  organizationalUnit: "PWRview",
  commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
  serialNumber: "APCBPGN2202-AF250300028",
  ipAddress: "10.10.10.10",
  curve: "secp384r1" // Optional: P-256, P-384 (default), or P-521
});
```

## Key Fixes in the New Version

### 1. Signature Algorithm
- **Changed from:** `SHA384withECDSA` ❌
- **Changed to:** `SHA256withECDSA` ✅

### 2. Subject Alternative Name (SAN)
- **Added:** IP Address extension (`10.10.10.10`)
- This was **missing** in the old version

### 3. Curve Selection
- **Added:** Support for multiple ECC curves
- **Supported curves:**
  - `secp256r1` (P-256) - 256-bit, faster, lower security
  - `secp384r1` (P-384) - 384-bit, balanced (default)
  - `secp521r1` (P-521) - 521-bit, maximum security

### 4. Better API Design
- Using a params object is more maintainable
- Easier to add optional parameters
- Better TypeScript support
- Default values for optional fields

## Benefits of the New Approach

1. **Cleaner Code**: Single parameter object instead of many positional arguments
2. **Optional Parameters**: Easy to specify only what you need
3. **Type Safety**: Full TypeScript support with interfaces
4. **Maintainability**: Adding new parameters doesn't break existing code
5. **Default Values**: Sensible defaults for common use cases

## Files to Update

1. ✅ `android/src/main/java/com/ecccsr/CSRModule.java` - Java implementation
2. ✅ `src/index.ts` - TypeScript interface
3. 🔄 Update any existing usage in your app code

## Testing

After updating, verify the CSR output with:
```bash
openssl req -in csr.csr -noout -text
```

Expected output should show:
- `Signature Algorithm: ecdsa-with-SHA256` ✅
- `X509v3 Subject Alternative Name: IP Address:10.10.10.10` ✅
- `X509v3 Key Usage: critical Digital Signature, Key Agreement` ✅
- `X509v3 Extended Key Usage: TLS Web Client Authentication` ✅