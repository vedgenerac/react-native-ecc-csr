//
//  EccCsrGenerator.m
//  react-native-ecc-csr
//

#import "EccCsrGenerator.h"
#import <React/RCTLog.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

@implementation EccCsrGenerator

RCT_EXPORT_MODULE();

- (int)keySizeForCurve:(NSString *)curve {
    if ([curve isEqualToString:@"P-256"]) {
        return 256;
    } else if ([curve isEqualToString:@"P-384"]) {
        return 384;
    } else if ([curve isEqualToString:@"P-521"]) {
        return 521;
    }
    return 384; // Default
}

RCT_EXPORT_METHOD(generateCSR:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        NSString *commonName = options[@"commonName"];
        NSString *serialNumber = options[@"serialNumber"];
        NSString *country = options[@"country"];
        NSString *state = options[@"state"];
        NSString *locality = options[@"locality"];
        NSString *organization = options[@"organization"];
        NSString *organizationalUnit = options[@"organizationalUnit"];
        NSString *ipAddress = options[@"ipAddress"];
        NSString *curve = options[@"curve"] ?: @"P-384";
        NSString *keyAlias = options[@"keyAlias"] ?: @"ECC_CSR_KEY";
        
        if (!commonName || commonName.length == 0) {
            reject(@"invalid_params", @"commonName is required", nil);
            return;
        }
        
        // Generate ECC key pair
        int keySize = [self keySizeForCurve:curve];
        
        NSDictionary *privateKeyAttrs = @{
            (__bridge id)kSecAttrIsPermanent: @YES,
            (__bridge id)kSecAttrApplicationTag: [keyAlias dataUsingEncoding:NSUTF8StringEncoding]
        };
        
        NSDictionary *keyPairAttrs = @{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits: @(keySize),
            (__bridge id)kSecPrivateKeyAttrs: privateKeyAttrs
        };
        
        CFErrorRef error = NULL;
        SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyPairAttrs, &error);
        
        if (error != NULL) {
            NSError *nsError = (__bridge NSError *)error;
            reject(@"key_generation_failed", nsError.localizedDescription, nsError);
            CFRelease(error);
            return;
        }
        
        SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
        if (!publicKey) {
            CFRelease(privateKey);
            reject(@"public_key_failed", @"Failed to extract public key", nil);
            return;
        }
        
        // Export public key
        CFErrorRef exportError = NULL;
        CFDataRef publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError);
        
        if (exportError != NULL) {
            NSError *nsError = (__bridge NSError *)exportError;
            CFRelease(privateKey);
            CFRelease(publicKey);
            CFRelease(exportError);
            reject(@"public_key_export_failed", nsError.localizedDescription, nsError);
            return;
        }
        
        NSString *publicKeyPEM = [self createPublicKeyPEM:(__bridge NSData *)publicKeyData curve:curve];
        
        // Build CSR
        NSData *csrData = [self buildCSRWithPrivateKey:privateKey
                                             publicKey:publicKey
                                            commonName:commonName
                                          serialNumber:serialNumber
                                               country:country
                                                 state:state
                                              locality:locality
                                          organization:organization
                                   organizationalUnit:organizationalUnit
                                             ipAddress:ipAddress
                                                 curve:curve];
        
        CFRelease(privateKey);
        CFRelease(publicKey);
        CFRelease(publicKeyData);
        
        if (!csrData) {
            reject(@"csr_generation_failed", @"Failed to generate CSR", nil);
            return;
        }
        
        NSString *csrPEM = [self createCSRPEM:csrData];
        
        NSDictionary *result = @{
            @"csr": csrPEM,
            @"publicKey": publicKeyPEM
        };
        
        resolve(result);
        
    } @catch (NSException *exception) {
        reject(@"exception", exception.reason, nil);
    }
}

RCT_EXPORT_METHOD(getPublicKey:(NSString *)keyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: [keyAlias dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecReturnRef: @YES
    };
    
    CFTypeRef privateKeyRef = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &privateKeyRef);
    
    if (status != errSecSuccess || !privateKeyRef) {
        reject(@"key_not_found", @"Key pair not found", nil);
        return;
    }
    
    SecKeyRef privateKey = (SecKeyRef)privateKeyRef;
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    
    if (!publicKey) {
        CFRelease(privateKey);
        reject(@"public_key_failed", @"Failed to extract public key", nil);
        return;
    }
    
    CFErrorRef error = NULL;
    CFDataRef publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
    
    CFRelease(privateKey);
    CFRelease(publicKey);
    
    if (error != NULL) {
        NSError *nsError = (__bridge NSError *)error;
        CFRelease(error);
        reject(@"public_key_export_failed", nsError.localizedDescription, nsError);
        return;
    }
    
    NSString *publicKeyPEM = [self createPublicKeyPEM:(__bridge NSData *)publicKeyData curve:@"P-384"];
    CFRelease(publicKeyData);
    
    resolve(publicKeyPEM);
}

RCT_EXPORT_METHOD(deleteKeyPair:(NSString *)keyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: [keyAlias dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom
    };
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    
    if (status == errSecSuccess || status == errSecItemNotFound) {
        resolve(@YES);
    } else {
        reject(@"delete_failed", @"Failed to delete key pair", nil);
    }
}

RCT_EXPORT_METHOD(hasKeyPair:(NSString *)keyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: [keyAlias dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecReturnRef: @YES
    };
    
    CFTypeRef keyRef = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &keyRef);
    
    if (keyRef) {
        CFRelease(keyRef);
    }
    
    resolve(@(status == errSecSuccess));
}

#pragma mark - Helper Methods

- (NSData *)buildCSRWithPrivateKey:(SecKeyRef)privateKey
                         publicKey:(SecKeyRef)publicKey
                        commonName:(NSString *)commonName
                      serialNumber:(NSString *)serialNumber
                           country:(NSString *)country
                             state:(NSString *)state
                          locality:(NSString *)locality
                      organization:(NSString *)organization
               organizationalUnit:(NSString *)organizationalUnit
                         ipAddress:(NSString *)ipAddress
                             curve:(NSString *)curve
{
    NSMutableData *csrData = [NSMutableData data];
    
    // Build subject DN
    NSMutableArray *subjectComponents = [NSMutableArray array];
    
    if (country.length > 0) {
        [subjectComponents addObject:@{@"type": @"C", @"value": country}];
    }
    if (state.length > 0) {
        [subjectComponents addObject:@{@"type": @"ST", @"value": state}];
    }
    if (locality.length > 0) {
        [subjectComponents addObject:@{@"type": @"L", @"value": locality}];
    }
    if (organization.length > 0) {
        [subjectComponents addObject:@{@"type": @"O", @"value": organization}];
    }
    if (organizationalUnit.length > 0) {
        [subjectComponents addObject:@{@"type": @"OU", @"value": organizationalUnit}];
    }
    
    // CN with serialNumber
    NSString *cnValue = commonName;
    if (serialNumber.length > 0) {
        cnValue = [NSString stringWithFormat:@"%@/serialNumber=%@", commonName, serialNumber];
    }
    [subjectComponents addObject:@{@"type": @"CN", @"value": cnValue}];
    
    NSData *subjectData = [self encodeSubject:subjectComponents];
    NSData *publicKeyInfo = [self encodePublicKeyInfo:publicKey curve:curve];
    NSData *extensionsData = [self encodeExtensions:ipAddress];
    
    // Build CertificationRequestInfo
    NSData *version = [self encodeInteger:0];
    NSData *certRequestInfo = [self encodeSequence:@[version, subjectData, publicKeyInfo, extensionsData]];
    
    // Sign the request
    CFErrorRef error = NULL;
    CFDataRef signature = SecKeyCreateSignature(privateKey,
                                                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                                (__bridge CFDataRef)certRequestInfo,
                                                &error);
    
    if (error != NULL || !signature) {
        if (error) CFRelease(error);
        return nil;
    }
    
    NSData *signatureAlgorithm = [self encodeSignatureAlgorithm];
    NSData *signatureBitString = [self encodeBitString:(__bridge NSData *)signature];
    
    CFRelease(signature);
    
    // Build final CSR
    NSData *finalCSR = [self encodeSequence:@[certRequestInfo, signatureAlgorithm, signatureBitString]];
    
    return finalCSR;
}

- (NSData *)encodeSubject:(NSArray *)components {
    NSMutableArray *encodedComponents = [NSMutableArray array];
    
    NSDictionary *oidMap = @{
        @"C": @"\x06\x03\x55\x04\x06",
        @"ST": @"\x06\x03\x55\x04\x08",
        @"L": @"\x06\x03\x55\x04\x07",
        @"O": @"\x06\x03\x55\x04\x0a",
        @"OU": @"\x06\x03\x55\x04\x0b",
        @"CN": @"\x06\x03\x55\x04\x03"
    };
    
    for (NSDictionary *component in components) {
        NSString *type = component[@"type"];
        NSString *value = component[@"value"];
        
        NSData *oid = [oidMap[type] dataUsingEncoding:NSISOLatin1StringEncoding];
        NSData *valueData = [self encodeUTF8String:value];
        
        NSData *attrTypeAndValue = [self encodeSequence:@[oid, valueData]];
        NSData *rdnSet = [self encodeSet:@[attrTypeAndValue]];
        
        [encodedComponents addObject:rdnSet];
    }
    
    return [self encodeSequence:encodedComponents];
}

- (NSData *)encodePublicKeyInfo:(SecKeyRef)publicKey curve:(NSString *)curve {
    CFErrorRef error = NULL;
    CFDataRef publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
    
    if (error != NULL || !publicKeyData) {
        if (error) CFRelease(error);
        return nil;
    }
    
    // Algorithm identifier
    NSData *ecPublicKeyOID = [@"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" dataUsingEncoding:NSISOLatin1StringEncoding];
    
    NSData *curveOID;
    if ([curve isEqualToString:@"P-256"]) {
        curveOID = [@"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" dataUsingEncoding:NSISOLatin1StringEncoding];
    } else if ([curve isEqualToString:@"P-384"]) {
        curveOID = [@"\x06\x05\x2b\x81\x04\x00\x22" dataUsingEncoding:NSISOLatin1StringEncoding];
    } else if ([curve isEqualToString:@"P-521"]) {
        curveOID = [@"\x06\x05\x2b\x81\x04\x00\x23" dataUsingEncoding:NSISOLatin1StringEncoding];
    } else {
        curveOID = [@"\x06\x05\x2b\x81\x04\x00\x22" dataUsingEncoding:NSISOLatin1StringEncoding]; // Default P-384
    }
    
    NSData *algorithmId = [self encodeSequence:@[ecPublicKeyOID, curveOID]];
    NSData *publicKeyBitString = [self encodeBitString:(__bridge NSData *)publicKeyData];
    
    CFRelease(publicKeyData);
    
    return [self encodeSequence:@[algorithmId, publicKeyBitString]];
}

- (NSData *)encodeExtensions:(NSString *)ipAddress {
    NSMutableArray *extensions = [NSMutableArray array];
    
    // Key Usage extension (critical)
    NSData *keyUsageOID = [@"\x06\x03\x55\x1d\x0f" dataUsingEncoding:NSISOLatin1StringEncoding];
    NSData *criticalFlag = [@"\x01\x01\xff" dataUsingEncoding:NSISOLatin1StringEncoding];
    // Digital Signature (bit 0) and Key Agreement (bit 4) = 0x90 (10010000)
    NSData *keyUsageValue = [@"\x04\x04\x03\x02\x05\x80" dataUsingEncoding:NSISOLatin1StringEncoding];
    NSData *keyUsageExt = [self encodeSequence:@[keyUsageOID, criticalFlag, keyUsageValue]];
    [extensions addObject:keyUsageExt];
    
    // Extended Key Usage
    NSData *extKeyUsageOID = [@"\x06\x03\x55\x1d\x25" dataUsingEncoding:NSISOLatin1StringEncoding];
    NSData *clientAuthOID = [@"\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02" dataUsingEncoding:NSISOLatin1StringEncoding];
    NSData *extKeyUsageValueSeq = [self encodeSequence:@[clientAuthOID]];
    NSData *extKeyUsageValue = [self encodeOctetString:extKeyUsageValueSeq];
    NSData *extKeyUsageExt = [self encodeSequence:@[extKeyUsageOID, extKeyUsageValue]];
    [extensions addObject:extKeyUsageExt];
    
    // Subject Alternative Name (IP Address)
    if (ipAddress.length > 0) {
        NSData *sanOID = [@"\x06\x03\x55\x1d\x11" dataUsingEncoding:NSISOLatin1StringEncoding];
        NSArray *octets = [ipAddress componentsSeparatedByString:@"."];
        NSMutableData *ipData = [NSMutableData data];
        for (NSString *octet in octets) {
            uint8_t byte = (uint8_t)[octet intValue];
            [ipData appendBytes:&byte length:1];
        }
        NSData *ipTag = [self encodeWithTag:0x87 data:ipData];
        NSData *sanValueSeq = [self encodeSequence:@[ipTag]];
        NSData *sanValue = [self encodeOctetString:sanValueSeq];
        NSData *sanExt = [self encodeSequence:@[sanOID, sanValue]];
        [extensions addObject:sanExt];
    }
    
    NSData *extensionsSeq = [self encodeSequence:extensions];
    
    // Wrap in [0] EXPLICIT
    NSMutableData *result = [NSMutableData data];
    uint8_t tag = 0xA0;
    [result appendBytes:&tag length:1];
    NSData *length = [self encodeLength:extensionsSeq.length];
    [result appendData:length];
    [result appendData:extensionsSeq];
    
    return result;
}

- (NSData *)encodeSignatureAlgorithm {
    NSData *oid = [@"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02" dataUsingEncoding:NSISOLatin1StringEncoding];
    return [self encodeSequence:@[oid]];
}

// DER encoding helpers
- (NSData *)encodeInteger:(NSInteger)value {
    NSMutableData *data = [NSMutableData data];
    uint8_t tag = 0x02;
    [data appendBytes:&tag length:1];
    
    if (value == 0) {
        uint8_t len = 1;
        uint8_t val = 0;
        [data appendBytes:&len length:1];
        [data appendBytes:&val length:1];
    } else {
        NSMutableData *valueData = [NSMutableData data];
        NSInteger temp = value;
        while (temp > 0) {
            uint8_t byte = temp & 0xFF;
            [valueData replaceBytesInRange:NSMakeRange(0, 0) withBytes:&byte length:1];
            temp >>= 8;
        }
        
        // Add leading zero if high bit is set
        const uint8_t *bytes = [valueData bytes];
        if (bytes[0] & 0x80) {
            uint8_t zero = 0;
            [valueData replaceBytesInRange:NSMakeRange(0, 0) withBytes:&zero length:1];
        }
        
        NSData *length = [self encodeLength:valueData.length];
        [data appendData:length];
        [data appendData:valueData];
    }
    
    return data;
}

- (NSData *)encodeSequence:(NSArray *)items {
    NSMutableData *content = [NSMutableData data];
    for (id item in items) {
        if ([item isKindOfClass:[NSData class]]) {
            [content appendData:item];
        }
    }
    
    NSMutableData *data = [NSMutableData data];
    uint8_t tag = 0x30;
    [data appendBytes:&tag length:1];
    NSData *length = [self encodeLength:content.length];
    [data appendData:length];
    [data appendData:content];
    
    return data;
}

- (NSData *)encodeSet:(NSArray *)items {
    NSMutableData *content = [NSMutableData data];
    for (id item in items) {
        if ([item isKindOfClass:[NSData class]]) {
            [content appendData:item];
        }
    }
    
    NSMutableData *data = [NSMutableData data];
    uint8_t tag = 0x31;
    [data appendBytes:&tag length:1];
    NSData *length = [self encodeLength:content.length];
    [data appendData:length];
    [data appendData:content];
    
    return data;
}

- (NSData *)encodeUTF8String:(NSString *)string {
    NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *data = [NSMutableData data];
    uint8_t tag = 0x0C;
    [data appendBytes:&tag length:1];
    NSData *length = [self encodeLength:stringData.length];
    [data appendData:length];
    [data appendData:stringData];
    return data;
}

- (NSData *)encodeBitString:(NSData *)bits {
    NSMutableData *data = [NSMutableData data];
    uint8_t tag = 0x03;
    [data appendBytes:&tag length:1];
    NSData *length = [self encodeLength:bits.length + 1];
    [data appendData:length];
    uint8_t unusedBits = 0;
    [data appendBytes:&unusedBits length:1];
    [data appendData:bits];
    return data;
}

- (NSData *)encodeOctetString:(NSData *)octets {
    NSMutableData *data = [NSMutableData data];
    uint8_t tag = 0x04;
    [data appendBytes:&tag length:1];
    NSData *length = [self encodeLength:octets.length];
    [data appendData:length];
    [data appendData:octets];
    return data;
}

- (NSData *)encodeWithTag:(uint8_t)tag data:(NSData *)content {
    NSMutableData *data = [NSMutableData data];
    [data appendBytes:&tag length:1];
    NSData *length = [self encodeLength:content.length];
    [data appendData:length];
    [data appendData:content];
    return data;
}

- (NSData *)encodeLength:(NSUInteger)length {
    NSMutableData *data = [NSMutableData data];
    
    if (length < 128) {
        uint8_t len = (uint8_t)length;
        [data appendBytes:&len length:1];
    } else {
        NSMutableData *lengthData = [NSMutableData data];
        NSUInteger temp = length;
        while (temp > 0) {
            uint8_t byte = temp & 0xFF;
            [lengthData replaceBytesInRange:NSMakeRange(0, 0) withBytes:&byte length:1];
            temp >>= 8;
        }
        
        uint8_t firstByte = 0x80 | lengthData.length;
        [data appendBytes:&firstByte length:1];
        [data appendData:lengthData];
    }
    
    return data;
}

- (NSString *)createCSRPEM:(NSData *)csrData {
    NSString *base64 = [csrData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    return [NSString stringWithFormat:@"-----BEGIN CERTIFICATE REQUEST-----\n%@\n-----END CERTIFICATE REQUEST-----", base64];
}

- (NSString *)createPublicKeyPEM:(NSData *)publicKeyData curve:(NSString *)curve {
    // For ECC, we need to wrap the raw key in SubjectPublicKeyInfo structure
    NSData *ecPublicKeyOID = [@"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" dataUsingEncoding:NSISOLatin1StringEncoding];
    
    NSData *curveOID;
    if ([curve isEqualToString:@"P-256"]) {
        curveOID = [@"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" dataUsingEncoding:NSISOLatin1StringEncoding];
    } else if ([curve isEqualToString:@"P-384"]) {
        curveOID = [@"\x06\x05\x2b\x81\x04\x00\x22" dataUsingEncoding:NSISOLatin1StringEncoding];
    } else if ([curve isEqualToString:@"P-521"]) {
        curveOID = [@"\x06\x05\x2b\x81\x04\x00\x23" dataUsingEncoding:NSISOLatin1StringEncoding];
    } else {
        curveOID = [@"\x06\x05\x2b\x81\x04\x00\x22" dataUsingEncoding:NSISOLatin1StringEncoding];
    }
    
    NSData *algorithmId = [self encodeSequence:@[ecPublicKeyOID, curveOID]];
    NSData *publicKeyBitString = [self encodeBitString:publicKeyData];
    NSData *spki = [self encodeSequence:@[algorithmId, publicKeyBitString]];
    
    NSString *base64 = [spki base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    return [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----", base64];
}

@end
