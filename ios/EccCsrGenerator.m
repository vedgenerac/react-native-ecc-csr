//
//  EccCsrGenerator.m
//  react-native-ecc-csr
//
//  iOS native implementation for generating ECC Certificate Signing Requests
//

#import "EccCsrGenerator.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation EccCsrGenerator

RCT_EXPORT_MODULE()

// Export the generateCSR method to JavaScript
RCT_EXPORT_METHOD(generateCSR:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        // Extract parameters from options
        NSString *commonName = options[@"commonName"] ?: @"";
        NSString *serialNumber = options[@"serialNumber"] ?: @"";
        NSString *country = options[@"country"] ?: @"";
        NSString *state = options[@"state"] ?: @"";
        NSString *locality = options[@"locality"] ?: @"";
        NSString *organization = options[@"organization"] ?: @"";
        NSString *organizationalUnit = options[@"organizationalUnit"] ?: @"";
        NSString *ipAddress = options[@"ipAddress"] ?: @"";
        NSString *curve = options[@"curve"] ?: @"P-384";
        
        // Validate required parameters
        if (commonName.length == 0) {
            reject(@"INVALID_PARAM", @"commonName is required", nil);
            return;
        }
        
        // Generate ECC key pair
        NSError *error = nil;
        NSDictionary *keyPair = [self generateECKeyPairForCurve:curve error:&error];
        if (error) {
            reject(@"KEY_GENERATION_ERROR", error.localizedDescription, error);
            return;
        }
        
        SecKeyRef privateKey = (__bridge SecKeyRef)keyPair[@"privateKey"];
        SecKeyRef publicKey = (__bridge SecKeyRef)keyPair[@"publicKey"];
        
        // Get public key data
        NSData *publicKeyData = [self exportPublicKey:publicKey error:&error];
        if (error) {
            reject(@"PUBLIC_KEY_ERROR", error.localizedDescription, error);
            return;
        }
        
        // Build CSR
        NSData *csrData = [self buildCSRWithSubject:@{
            @"CN": commonName,
            @"serialNumber": serialNumber,
            @"C": country,
            @"ST": state,
            @"L": locality,
            @"O": organization,
            @"OU": organizationalUnit
        }
                                          publicKey:publicKey
                                         privateKey:privateKey
                                              curve:curve
                                          ipAddress:ipAddress
                                              error:&error];
        
        if (error) {
            reject(@"CSR_GENERATION_ERROR", error.localizedDescription, error);
            return;
        }
        
        // Convert to PEM format
        NSString *csrPEM = [self convertToPEM:csrData label:@"CERTIFICATE REQUEST"];
        NSString *publicKeyPEM = [self convertToPEM:publicKeyData label:@"PUBLIC KEY"];
        
        // Return result
        resolve(@{
            @"csr": csrPEM,
            @"publicKey": publicKeyPEM
        });
        
    } @catch (NSException *exception) {
        reject(@"EXCEPTION", exception.reason, nil);
    }
}

#pragma mark - Key Generation

- (NSDictionary *)generateECKeyPairForCurve:(NSString *)curveName error:(NSError **)error {
    // Map curve names to key sizes
    int keySize = 384; // Default P-384
    if ([curveName isEqualToString:@"P-256"]) {
        keySize = 256;
    } else if ([curveName isEqualToString:@"P-521"]) {
        keySize = 521;
    }
    
    // Create unique tag for this key pair
    NSString *tag = [NSString stringWithFormat:@"com.ecccsrgen.keypair.%@", [[NSUUID UUID] UUIDString]];
    NSData *tagData = [tag dataUsingEncoding:NSUTF8StringEncoding];
    
    // Key generation parameters
    NSDictionary *parameters = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @(keySize),
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent: @NO,
            (id)kSecAttrApplicationTag: tagData,
        }
    };
    
    CFErrorRef cfError = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)parameters, &cfError);
    
    if (cfError) {
        if (error) {
            *error = (__bridge_transfer NSError *)cfError;
        }
        return nil;
    }
    
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    
    return @{
        @"privateKey": (__bridge_transfer id)privateKey,
        @"publicKey": (__bridge_transfer id)publicKey
    };
}

- (NSData *)exportPublicKey:(SecKeyRef)publicKey error:(NSError **)error {
    CFErrorRef cfError = NULL;
    NSData *keyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(publicKey, &cfError);
    
    if (cfError) {
        if (error) {
            *error = (__bridge_transfer NSError *)cfError;
        }
        return nil;
    }
    
    // Wrap in SubjectPublicKeyInfo structure
    NSData *spki = [self wrapPublicKeyInSPKI:keyData curve:[self getCurveFromKey:publicKey]];
    return spki;
}

- (NSString *)getCurveFromKey:(SecKeyRef)key {
    NSDictionary *attributes = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(key);
    NSNumber *keySize = attributes[(id)kSecAttrKeySizeInBits];
    
    if ([keySize intValue] == 256) return @"P-256";
    if ([keySize intValue] == 384) return @"P-384";
    if ([keySize intValue] == 521) return @"P-521";
    
    return @"P-384";
}

#pragma mark - CSR Building

- (NSData *)buildCSRWithSubject:(NSDictionary *)subject
                      publicKey:(SecKeyRef)publicKey
                     privateKey:(SecKeyRef)privateKey
                          curve:(NSString *)curve
                      ipAddress:(NSString *)ipAddress
                          error:(NSError **)error {
    
    // Build the CSR components
    NSData *subjectDN = [self encodeDN:subject];
    NSData *publicKeyInfo = [self exportPublicKey:publicKey error:error];
    if (*error) return nil;
    
    NSData *extensions = [self buildExtensions:ipAddress];
    NSData *attributes = [self buildAttributes:extensions];
    
    // Build CertificationRequestInfo
    NSData *certRequestInfo = [self buildCertificationRequestInfo:subjectDN
                                                       publicKeyInfo:publicKeyInfo
                                                          attributes:attributes];
    
    // Sign the CertificationRequestInfo
    NSData *signature = [self signData:certRequestInfo withPrivateKey:privateKey error:error];
    if (*error) return nil;
    
    // Build final CSR
    NSData *csr = [self buildFinalCSR:certRequestInfo signature:signature curve:curve];
    
    return csr;
}

- (NSData *)buildCertificationRequestInfo:(NSData *)subject
                            publicKeyInfo:(NSData *)publicKeyInfo
                               attributes:(NSData *)attributes {
    NSMutableData *certRequestInfo = [NSMutableData data];
    
    // Version (INTEGER 0)
    NSData *version = [self encodeInteger:0];
    
    // Combine all components
    [certRequestInfo appendData:version];
    [certRequestInfo appendData:subject];
    [certRequestInfo appendData:publicKeyInfo];
    [certRequestInfo appendData:attributes];
    
    // Wrap in SEQUENCE
    return [self wrapInSequence:certRequestInfo];
}

- (NSData *)buildFinalCSR:(NSData *)certRequestInfo
                signature:(NSData *)signature
                    curve:(NSString *)curve {
    NSMutableData *csr = [NSMutableData data];
    
    // Add CertificationRequestInfo
    [csr appendData:certRequestInfo];
    
    // Add SignatureAlgorithm (ecdsa-with-SHA256)
    NSData *signatureAlgorithm = [self encodeSignatureAlgorithm];
    [csr appendData:signatureAlgorithm];
    
    // Add Signature (BIT STRING)
    NSData *signatureBitString = [self encodeBitString:signature];
    [csr appendData:signatureBitString];
    
    // Wrap entire CSR in SEQUENCE
    return [self wrapInSequence:csr];
}

#pragma mark - DN Encoding

- (NSData *)encodeDN:(NSDictionary *)subject {
    NSMutableData *dn = [NSMutableData data];
    
    // Order matters for DN: C, ST, L, O, OU, CN, serialNumber
    NSArray *order = @[@"C", @"ST", @"L", @"O", @"OU", @"CN", @"serialNumber"];
    
    for (NSString *key in order) {
        NSString *value = subject[key];
        if (value && value.length > 0) {
            NSData *rdn = [self encodeRDN:key value:value];
            [dn appendData:rdn];
        }
    }
    
    return [self wrapInSequence:dn];
}

- (NSData *)encodeRDN:(NSString *)key value:(NSString *)value {
    // Get OID for attribute
    NSData *oid = [self getOIDForAttribute:key];
    NSData *stringValue = [self encodeUTF8String:value];
    
    // AttributeTypeAndValue = SEQUENCE { type OID, value ANY }
    NSMutableData *atav = [NSMutableData data];
    [atav appendData:oid];
    [atav appendData:stringValue];
    NSData *atavSeq = [self wrapInSequence:atav];
    
    // RDN = SET OF AttributeTypeAndValue
    return [self wrapInSet:atavSeq];
}

- (NSData *)getOIDForAttribute:(NSString *)attribute {
    NSDictionary *oidMap = @{
        @"C": @"2.5.4.6",           // countryName
        @"ST": @"2.5.4.8",          // stateOrProvinceName
        @"L": @"2.5.4.7",           // localityName
        @"O": @"2.5.4.10",          // organizationName
        @"OU": @"2.5.4.11",         // organizationalUnitName
        @"CN": @"2.5.4.3",          // commonName
        @"serialNumber": @"2.5.4.5" // serialNumber
    };
    
    return [self encodeOID:oidMap[attribute]];
}

#pragma mark - Extensions

- (NSData *)buildExtensions:(NSString *)ipAddress {
    NSMutableData *extensions = [NSMutableData data];
    
    // Key Usage extension (critical)
    NSData *keyUsage = [self buildKeyUsageExtension];
    [extensions appendData:keyUsage];
    
    // Extended Key Usage extension
    NSData *extKeyUsage = [self buildExtendedKeyUsageExtension];
    [extensions appendData:extKeyUsage];
    
    // Subject Alternative Name extension (if IP provided)
    if (ipAddress && ipAddress.length > 0) {
        NSData *san = [self buildSubjectAltNameExtension:ipAddress];
        [extensions appendData:san];
    }
    
    return [self wrapInSequence:extensions];
}

- (NSData *)buildKeyUsageExtension {
    // KeyUsage: digitalSignature (0), keyAgreement (4)
    // Bit string: 10001000 = 0x88 (in DER, first byte is unused bits count)
    NSData *keyUsageBits = [NSData dataWithBytes:(unsigned char[]){0x03, 0x02, 0x05, 0x88} length:4];
    
    return [self buildExtension:@"2.5.29.15" critical:YES value:keyUsageBits];
}

- (NSData *)buildExtendedKeyUsageExtension {
    // ExtKeyUsage: TLS Web Client Authentication (1.3.6.1.5.5.7.3.2)
    NSData *clientAuthOID = [self encodeOID:@"1.3.6.1.5.5.7.3.2"];
    NSData *sequence = [self wrapInSequence:clientAuthOID];
    
    return [self buildExtension:@"2.5.29.37" critical:NO value:sequence];
}

- (NSData *)buildSubjectAltNameExtension:(NSString *)ipAddress {
    // Parse IP address
    NSArray *octets = [ipAddress componentsSeparatedByString:@"."];
    if (octets.count != 4) {
        return [NSData data];
    }
    
    // Build IP address (CONTEXT SPECIFIC [7])
    unsigned char ipBytes[4];
    for (int i = 0; i < 4; i++) {
        ipBytes[i] = (unsigned char)[octets[i] intValue];
    }
    
    NSMutableData *ipTag = [NSMutableData data];
    unsigned char tag = 0x87; // CONTEXT [7]
    unsigned char length = 0x04;
    [ipTag appendBytes:&tag length:1];
    [ipTag appendBytes:&length length:1];
    [ipTag appendBytes:ipBytes length:4];
    
    NSData *sanSequence = [self wrapInSequence:ipTag];
    
    return [self buildExtension:@"2.5.29.17" critical:NO value:sanSequence];
}

- (NSData *)buildExtension:(NSString *)oidString critical:(BOOL)critical value:(NSData *)value {
    NSMutableData *extension = [NSMutableData data];
    
    // Extension OID
    [extension appendData:[self encodeOID:oidString]];
    
    // Critical flag (if true)
    if (critical) {
        NSData *criticalBool = [NSData dataWithBytes:(unsigned char[]){0x01, 0x01, 0xFF} length:3];
        [extension appendData:criticalBool];
    }
    
    // Extension value (OCTET STRING)
    [extension appendData:[self encodeOctetString:value]];
    
    return [self wrapInSequence:extension];
}

- (NSData *)buildAttributes:(NSData *)extensions {
    // Attributes = CONTEXT SPECIFIC [0]
    // Contains extensionRequest attribute
    
    // Extension Request OID: 1.2.840.113549.1.9.14
    NSData *extReqOID = [self encodeOID:@"1.2.840.113549.1.9.14"];
    
    // Wrap extensions in SET
    NSData *extSet = [self wrapInSet:extensions];
    
    // Build attribute SEQUENCE
    NSMutableData *attribute = [NSMutableData data];
    [attribute appendData:extReqOID];
    [attribute appendData:extSet];
    NSData *attrSeq = [self wrapInSequence:attribute];
    
    // Wrap in CONTEXT SPECIFIC [0]
    return [self wrapInContext:attrSeq tag:0];
}

#pragma mark - Signing

- (NSData *)signData:(NSData *)data withPrivateKey:(SecKeyRef)privateKey error:(NSError **)error {
    // Hash the data with SHA-256
    NSMutableData *hash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash.mutableBytes);
    
    // Sign the hash
    CFErrorRef cfError = NULL;
    NSData *signature = (__bridge_transfer NSData *)SecKeyCreateSignature(
        privateKey,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        (__bridge CFDataRef)hash,
        &cfError
    );
    
    if (cfError) {
        if (error) {
            *error = (__bridge_transfer NSError *)cfError;
        }
        return nil;
    }
    
    return signature;
}

- (NSData *)encodeSignatureAlgorithm {
    // ecdsa-with-SHA256 OID: 1.2.840.10045.4.3.2
    NSData *oid = [self encodeOID:@"1.2.840.10045.4.3.2"];
    return [self wrapInSequence:oid];
}

#pragma mark - Public Key Info

- (NSData *)wrapPublicKeyInSPKI:(NSData *)publicKeyData curve:(NSString *)curve {
    NSMutableData *spki = [NSMutableData data];
    
    // Algorithm Identifier
    NSData *algorithm = [self encodeAlgorithmIdentifier:curve];
    [spki appendData:algorithm];
    
    // Public Key (BIT STRING)
    NSData *publicKeyBitString = [self encodeBitString:publicKeyData];
    [spki appendData:publicKeyBitString];
    
    return [self wrapInSequence:spki];
}

- (NSData *)encodeAlgorithmIdentifier:(NSString *)curve {
    NSMutableData *algId = [NSMutableData data];
    
    // ECC Public Key OID: 1.2.840.10045.2.1
    NSData *eccOID = [self encodeOID:@"1.2.840.10045.2.1"];
    [algId appendData:eccOID];
    
    // Curve OID
    NSString *curveOID = @"1.2.840.10045.3.1.7"; // Default P-256
    if ([curve isEqualToString:@"P-384"]) {
        curveOID = @"1.3.132.0.34"; // secp384r1
    } else if ([curve isEqualToString:@"P-521"]) {
        curveOID = @"1.3.132.0.35"; // secp521r1
    }
    
    NSData *curveOIDData = [self encodeOID:curveOID];
    [algId appendData:curveOIDData];
    
    return [self wrapInSequence:algId];
}

#pragma mark - ASN.1 Encoding Primitives

- (NSData *)encodeInteger:(NSInteger)value {
    NSMutableData *data = [NSMutableData data];
    unsigned char tag = 0x02; // INTEGER
    unsigned char length = 0x01;
    unsigned char val = (unsigned char)value;
    
    [data appendBytes:&tag length:1];
    [data appendBytes:&length length:1];
    [data appendBytes:&val length:1];
    
    return data;
}

- (NSData *)encodeOID:(NSString *)oidString {
    NSArray *components = [oidString componentsSeparatedByString:@"."];
    NSMutableData *oidData = [NSMutableData data];
    
    // First two components are encoded as 40*first + second
    unsigned char firstByte = [components[0] intValue] * 40 + [components[1] intValue];
    [oidData appendBytes:&firstByte length:1];
    
    // Remaining components
    for (NSInteger i = 2; i < components.count; i++) {
        NSInteger value = [components[i] integerValue];
        NSData *encoded = [self encodeOIDComponent:value];
        [oidData appendData:encoded];
    }
    
    // Add tag and length
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x06; // OID
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:oidData.length]];
    [result appendData:oidData];
    
    return result;
}

- (NSData *)encodeOIDComponent:(NSInteger)value {
    NSMutableData *data = [NSMutableData data];
    
    if (value < 128) {
        unsigned char byte = (unsigned char)value;
        [data appendBytes:&byte length:1];
    } else {
        // Encode in base 128
        NSMutableArray *bytes = [NSMutableArray array];
        while (value > 0) {
            [bytes insertObject:@(value & 0x7F) atIndex:0];
            value >>= 7;
        }
        
        for (NSInteger i = 0; i < bytes.count; i++) {
            unsigned char byte = [bytes[i] unsignedCharValue];
            if (i < bytes.count - 1) {
                byte |= 0x80; // Set continuation bit
            }
            [data appendBytes:&byte length:1];
        }
    }
    
    return data;
}

- (NSData *)encodeUTF8String:(NSString *)string {
    NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [NSMutableData data];
    
    unsigned char tag = 0x0C; // UTF8String
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:stringData.length]];
    [result appendData:stringData];
    
    return result;
}

- (NSData *)encodeOctetString:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x04; // OCTET STRING
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)encodeBitString:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x03; // BIT STRING
    unsigned char unusedBits = 0x00;
    
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length + 1]];
    [result appendBytes:&unusedBits length:1];
    [result appendData:data];
    
    return result;
}

- (NSData *)wrapInSequence:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x30; // SEQUENCE
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)wrapInSet:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x31; // SET
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)wrapInContext:(NSData *)data tag:(unsigned char)contextTag {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0xA0 | contextTag; // CONTEXT SPECIFIC
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)encodeLength:(NSUInteger)length {
    NSMutableData *result = [NSMutableData data];
    
    if (length < 128) {
        unsigned char byte = (unsigned char)length;
        [result appendBytes:&byte length:1];
    } else {
        // Long form
        NSMutableArray *bytes = [NSMutableArray array];
        NSUInteger temp = length;
        while (temp > 0) {
            [bytes insertObject:@(temp & 0xFF) atIndex:0];
            temp >>= 8;
        }
        
        unsigned char firstByte = 0x80 | bytes.count;
        [result appendBytes:&firstByte length:1];
        
        for (NSNumber *byte in bytes) {
            unsigned char b = [byte unsignedCharValue];
            [result appendBytes:&b length:1];
        }
    }
    
    return result;
}

#pragma mark - PEM Conversion

- (NSString *)convertToPEM:(NSData *)data label:(NSString *)label {
    NSString *base64 = [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    return [NSString stringWithFormat:@"-----BEGIN %@-----\n%@\n-----END %@-----",
            label, base64, label];
}

@end
