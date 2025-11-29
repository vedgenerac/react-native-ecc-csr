//
//  EccCsrGenerator.m
//  react-native-ecc-csr
//
//  iOS native module for generating ECC Certificate Signing Requests
//

#import "EccCsrGenerator.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

// Private interface for helper methods
@interface EccCsrGenerator ()

- (NSData *)createSubjectFromDN:(NSString *)dn;
- (NSData *)createRDN:(NSString *)attribute value:(NSString *)value;
- (NSData *)getOIDForAttribute:(NSString *)attribute;
- (NSData *)encodeAttributeValue:(NSString *)value;
- (NSData *)createSubjectPublicKeyInfo:(NSData *)publicKeyData keySize:(int)keySize;
- (NSData *)createAlgorithmIdentifier:(int)keySize;
- (NSData *)createExtensions:(NSString *)ipAddress phoneDeviceId:(NSString *)phoneDeviceId;
- (NSData *)createKeyUsageExtension;
- (NSData *)createExtendedKeyUsageExtension;
- (NSData *)createSANExtensionWithIP:(NSString *)ipAddress phoneDeviceId:(NSString *)phoneDeviceId;
- (NSData *)createGeneralNames:(NSString *)ipAddress phoneDeviceId:(NSString *)phoneDeviceId;
- (NSData *)encodeIPAddress:(NSString *)ipAddress;
- (NSData *)encodeOtherName:(NSString *)phoneDeviceId;
- (NSData *)createAttributes:(NSData *)extensionsData;
- (NSData *)createCertificationRequestInfo:(NSData *)subject spki:(NSData *)spki attributes:(NSData *)attributes;
- (NSData *)buildFinalCSR:(NSData *)certRequestInfo signature:(NSData *)signature;
- (NSData *)createSignatureAlgorithmIdentifier;
- (NSData *)encodeOID:(NSString *)oid;
- (NSData *)encodeOIDComponent:(NSInteger)value;
- (NSData *)encodeDERLength:(NSUInteger)length;
- (NSString *)convertToPEM:(NSData *)derData;

@end

@implementation EccCsrGenerator

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(generateCSR:(NSDictionary *)params
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        // Extract parameters from params
        NSString *commonName = params[@"commonName"] ?: @"";
        NSString *serialNumber = params[@"serialNumber"] ?: @"";
        NSString *country = params[@"country"] ?: @"";
        NSString *state = params[@"state"] ?: @"";
        NSString *locality = params[@"locality"] ?: @"";
        NSString *organization = params[@"organization"] ?: @"";
        NSString *organizationalUnit = params[@"organizationalUnit"] ?: @"";
        NSString *ipAddress = params[@"ipAddress"] ?: @"";
        NSString *phoneDeviceId = params[@"phoneDeviceId"] ?: @"";
        NSString *curve = params[@"curve"] ?: @"secp384r1";  // Default to secp384r1
        NSString *privateKeyAlias = params[@"privateKeyAlias"];
        
        // Determine key size based on curve
        int keySize;
        if ([curve isEqualToString:@"secp256r1"] || [curve isEqualToString:@"P-256"]) {
            keySize = 256;
        } else if ([curve isEqualToString:@"secp384r1"] || [curve isEqualToString:@"P-384"]) {
            keySize = 384;
        } else if ([curve isEqualToString:@"secp521r1"] || [curve isEqualToString:@"P-521"]) {
            keySize = 521;
        } else {
            keySize = 384; // Default to P-384
        }
        
        // Generate ECC key pair
        NSDictionary *keyAttributes = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @(keySize),
            (id)kSecAttrIsPermanent: @NO
        };
        
        CFErrorRef error = NULL;
        SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, &error);
        
        if (error != NULL) {
            NSError *nsError = (__bridge_transfer NSError *)error;
            reject(@"KEY_GENERATION_ERROR", nsError.localizedDescription, nsError);
            return;
        }
        
        SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
        
        if (publicKey == NULL) {
            CFRelease(privateKey);
            reject(@"PUBLIC_KEY_ERROR", @"Failed to extract public key", nil);
            return;
        }
        
        // Build subject DN
        NSMutableString *subjectDN = [NSMutableString string];
        
        if (country && country.length > 0) {
            [subjectDN appendFormat:@"C=%@, ", country];
        }
        if (state && state.length > 0) {
            [subjectDN appendFormat:@"ST=%@, ", state];
        }
        if (locality && locality.length > 0) {
            [subjectDN appendFormat:@"L=%@, ", locality];
        }
        if (organization && organization.length > 0) {
            [subjectDN appendFormat:@"O=%@, ", organization];
        }
        if (organizationalUnit && organizationalUnit.length > 0) {
            [subjectDN appendFormat:@"OU=%@, ", organizationalUnit];
        }
        
        [subjectDN appendFormat:@"CN=%@", commonName];
        
        if (serialNumber && serialNumber.length > 0) {
            [subjectDN appendFormat:@"/serialNumber=%@", serialNumber];
        }
        
        // Create subject from DN string
        NSData *subjectData = [self createSubjectFromDN:subjectDN];
        
        // Get public key data
        CFErrorRef pubKeyError = NULL;
        NSData *publicKeyData = (NSData *)CFBridgingRelease(
            SecKeyCopyExternalRepresentation(publicKey, &pubKeyError)
        );
        
        if (pubKeyError != NULL) {
            NSError *nsError = (__bridge_transfer NSError *)pubKeyError;
            CFRelease(privateKey);
            CFRelease(publicKey);
            reject(@"PUBLIC_KEY_EXPORT_ERROR", nsError.localizedDescription, nsError);
            return;
        }
        
        // Create Subject Public Key Info
        NSData *spki = [self createSubjectPublicKeyInfo:publicKeyData keySize:keySize];
        
        // Create extensions
        NSData *extensionsData = [self createExtensions:ipAddress phoneDeviceId:phoneDeviceId];
        
        // Create attributes (with extensions)
        NSData *attributesData = [self createAttributes:extensionsData];
        
        // Create CertificationRequestInfo
        NSData *certRequestInfo = [self createCertificationRequestInfo:subjectData
                                                                   spki:spki
                                                             attributes:attributesData];
        
        // Sign the CSR
        CFErrorRef signError = NULL;
        NSData *signature = (NSData *)CFBridgingRelease(
            SecKeyCreateSignature(privateKey,
                                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                (__bridge CFDataRef)certRequestInfo,
                                &signError)
        );
        
        if (signError != NULL) {
            NSError *nsError = (__bridge_transfer NSError *)signError;
            CFRelease(privateKey);
            CFRelease(publicKey);
            reject(@"SIGNING_ERROR", nsError.localizedDescription, nsError);
            return;
        }
        
        // Build final CSR
        NSData *csrData = [self buildFinalCSR:certRequestInfo signature:signature];
        
        // Convert to PEM
        NSString *csrPEM = [self convertToPEM:csrData];
        
        // Get public key in PEM format
        NSString *publicKeyPEM = [publicKeyData base64EncodedStringWithOptions:0];
        
        // Clean up
        CFRelease(privateKey);
        CFRelease(publicKey);
        
        // Return result
        NSDictionary *result = @{
            @"csr": csrPEM,
            @"publicKey": publicKeyPEM
        };
        
        resolve(result);
        
    } @catch (NSException *exception) {
        reject(@"CSR_GENERATION_ERROR", exception.reason, nil);
    }
}

#pragma mark - Subject DN Creation

- (NSData *)createSubjectFromDN:(NSString *)dn {
    NSMutableData *subjectData = [NSMutableData data];
    
    // SEQUENCE tag
    [subjectData appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *subjectContent = [NSMutableData data];
    
    // Split DN by commas
    NSArray *components = [dn componentsSeparatedByString:@", "];
    
    for (NSString *component in components) {
        NSArray *keyValue = [component componentsSeparatedByString:@"="];
        if (keyValue.count == 2) {
            NSString *key = [keyValue[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSString *value = [keyValue[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            
            NSData *rdnData = [self createRDN:key value:value];
            [subjectContent appendData:rdnData];
        }
    }
    
    // Add length
    NSData *lengthData = [self encodeDERLength:subjectContent.length];
    [subjectData appendData:lengthData];
    [subjectData appendData:subjectContent];
    
    return subjectData;
}

- (NSData *)createRDN:(NSString *)attribute value:(NSString *)value {
    NSMutableData *rdnData = [NSMutableData data];
    
    // SET tag
    [rdnData appendBytes:(uint8_t[]){0x31} length:1];
    
    NSMutableData *setContent = [NSMutableData data];
    
    // SEQUENCE tag
    [setContent appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *seqContent = [NSMutableData data];
    
    // Get OID for attribute
    NSData *oidData = [self getOIDForAttribute:attribute];
    [seqContent appendData:oidData];
    
    // Value as PrintableString or UTF8String
    NSData *valueData = [self encodeAttributeValue:value];
    [seqContent appendData:valueData];
    
    // Add length for SEQUENCE
    NSData *seqLengthData = [self encodeDERLength:seqContent.length];
    [setContent appendData:seqLengthData];
    [setContent appendData:seqContent];
    
    // Add length for SET
    NSData *setLengthData = [self encodeDERLength:setContent.length];
    [rdnData appendData:setLengthData];
    [rdnData appendData:setContent];
    
    return rdnData;
}

- (NSData *)getOIDForAttribute:(NSString *)attribute {
    NSDictionary *oidMap = @{
        @"C": @"2.5.4.6",
        @"ST": @"2.5.4.8",
        @"L": @"2.5.4.7",
        @"O": @"2.5.4.10",
        @"OU": @"2.5.4.11",
        @"CN": @"2.5.4.3",
        @"serialNumber": @"2.5.4.5"
    };
    
    NSString *oid = oidMap[attribute];
    if (oid) {
        return [self encodeOID:oid];
    }
    
    // Default to CN if unknown
    return [self encodeOID:@"2.5.4.3"];
}

- (NSData *)encodeAttributeValue:(NSString *)value {
    NSMutableData *data = [NSMutableData data];
    
    // Use PrintableString (0x13) for simple values, UTF8String (0x0C) for others
    BOOL isPrintable = YES;
    NSCharacterSet *printableSet = [NSCharacterSet characterSetWithCharactersInString:
                                   @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"];
    
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if (![printableSet characterIsMember:c]) {
            isPrintable = NO;
            break;
        }
    }
    
    if (isPrintable) {
        // PrintableString
        [data appendBytes:(uint8_t[]){0x13} length:1];
    } else {
        // UTF8String
        [data appendBytes:(uint8_t[]){0x0C} length:1];
    }
    
    NSData *stringData = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSData *lengthData = [self encodeDERLength:stringData.length];
    [data appendData:lengthData];
    [data appendData:stringData];
    
    return data;
}

#pragma mark - Subject Public Key Info

- (NSData *)createSubjectPublicKeyInfo:(NSData *)publicKeyData keySize:(int)keySize {
    NSMutableData *spki = [NSMutableData data];
    
    // SEQUENCE tag
    [spki appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *spkiContent = [NSMutableData data];
    
    // Algorithm Identifier
    NSData *algorithmIdentifier = [self createAlgorithmIdentifier:keySize];
    [spkiContent appendData:algorithmIdentifier];
    
    // Subject Public Key (BIT STRING)
    NSMutableData *bitString = [NSMutableData data];
    [bitString appendBytes:(uint8_t[]){0x03} length:1]; // BIT STRING tag
    
    NSMutableData *bitStringContent = [NSMutableData data];
    [bitStringContent appendBytes:(uint8_t[]){0x00} length:1]; // No unused bits
    [bitStringContent appendData:publicKeyData];
    
    NSData *bitStringLength = [self encodeDERLength:bitStringContent.length];
    [bitString appendData:bitStringLength];
    [bitString appendData:bitStringContent];
    
    [spkiContent appendData:bitString];
    
    // Add length
    NSData *spkiLength = [self encodeDERLength:spkiContent.length];
    [spki appendData:spkiLength];
    [spki appendData:spkiContent];
    
    return spki;
}

- (NSData *)createAlgorithmIdentifier:(int)keySize {
    NSMutableData *algId = [NSMutableData data];
    
    // SEQUENCE tag
    [algId appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *algIdContent = [NSMutableData data];
    
    // OID for ecPublicKey: 1.2.840.10045.2.1
    NSData *ecPublicKeyOID = [self encodeOID:@"1.2.840.10045.2.1"];
    [algIdContent appendData:ecPublicKeyOID];
    
    // Named curve OID
    NSString *curveOID;
    if (keySize == 256) {
        curveOID = @"1.2.840.10045.3.1.7"; // secp256r1
    } else if (keySize == 384) {
        curveOID = @"1.3.132.0.34"; // secp384r1
    } else if (keySize == 521) {
        curveOID = @"1.3.132.0.35"; // secp521r1
    } else {
        curveOID = @"1.3.132.0.34"; // Default to secp384r1
    }
    
    NSData *namedCurveOID = [self encodeOID:curveOID];
    [algIdContent appendData:namedCurveOID];
    
    // Add length
    NSData *algIdLength = [self encodeDERLength:algIdContent.length];
    [algId appendData:algIdLength];
    [algId appendData:algIdContent];
    
    return algId;
}

#pragma mark - Extensions

- (NSData *)createExtensions:(NSString *)ipAddress phoneDeviceId:(NSString *)phoneDeviceId {
    NSMutableData *extensions = [NSMutableData data];
    
    // SEQUENCE tag
    [extensions appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *extensionsContent = [NSMutableData data];
    
    // Key Usage extension
    NSData *keyUsageExt = [self createKeyUsageExtension];
    [extensionsContent appendData:keyUsageExt];
    
    // Extended Key Usage extension
    NSData *extKeyUsageExt = [self createExtendedKeyUsageExtension];
    [extensionsContent appendData:extKeyUsageExt];
    
    // Subject Alternative Name extension (if IP or phoneDeviceId provided)
    if ((ipAddress && ipAddress.length > 0) || (phoneDeviceId && phoneDeviceId.length > 0)) {
        NSData *sanExt = [self createSANExtensionWithIP:ipAddress phoneDeviceId:phoneDeviceId];
        [extensionsContent appendData:sanExt];
    }
    
    // Add length
    NSData *extensionsLength = [self encodeDERLength:extensionsContent.length];
    [extensions appendData:extensionsLength];
    [extensions appendData:extensionsContent];
    
    return extensions;
}

- (NSData *)createKeyUsageExtension {
    NSMutableData *extension = [NSMutableData data];
    
    // SEQUENCE tag
    [extension appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *extContent = [NSMutableData data];
    
    // OID for keyUsage: 2.5.29.15
    NSData *oid = [self encodeOID:@"2.5.29.15"];
    [extContent appendData:oid];
    
    // Critical: TRUE
    [extContent appendBytes:(uint8_t[]){0x01, 0x01, 0xFF} length:3];
    
    // Extension value (OCTET STRING containing BIT STRING)
    NSMutableData *extValue = [NSMutableData data];
    [extValue appendBytes:(uint8_t[]){0x04} length:1]; // OCTET STRING tag
    
    // BIT STRING with keyUsage flags
    uint8_t bitStringValue[] = {0x03, 0x02, 0x05, 0x88};
    NSData *bitStringLength = [self encodeDERLength:sizeof(bitStringValue)];
    [extValue appendData:bitStringLength];
    [extValue appendBytes:bitStringValue length:sizeof(bitStringValue)];
    
    [extContent appendData:extValue];
    
    // Add length
    NSData *extLength = [self encodeDERLength:extContent.length];
    [extension appendData:extLength];
    [extension appendData:extContent];
    
    return extension;
}

- (NSData *)createExtendedKeyUsageExtension {
    NSMutableData *extension = [NSMutableData data];
    
    // SEQUENCE tag
    [extension appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *extContent = [NSMutableData data];
    
    // OID for extKeyUsage: 2.5.29.37
    NSData *oid = [self encodeOID:@"2.5.29.37"];
    [extContent appendData:oid];
    
    // Extension value (OCTET STRING containing SEQUENCE of OIDs)
    NSMutableData *extValue = [NSMutableData data];
    [extValue appendBytes:(uint8_t[]){0x04} length:1]; // OCTET STRING tag
    
    NSMutableData *oidSeq = [NSMutableData data];
    [oidSeq appendBytes:(uint8_t[]){0x30} length:1]; // SEQUENCE tag
    
    // OID for clientAuth: 1.3.6.1.5.5.7.3.2
    NSData *clientAuthOID = [self encodeOID:@"1.3.6.1.5.5.7.3.2"];
    
    NSData *oidSeqLength = [self encodeDERLength:clientAuthOID.length];
    [oidSeq appendData:oidSeqLength];
    [oidSeq appendData:clientAuthOID];
    
    NSData *extValueLength = [self encodeDERLength:oidSeq.length];
    [extValue appendData:extValueLength];
    [extValue appendData:oidSeq];
    
    [extContent appendData:extValue];
    
    // Add length
    NSData *extLength = [self encodeDERLength:extContent.length];
    [extension appendData:extLength];
    [extension appendData:extContent];
    
    return extension;
}

- (NSData *)createSANExtensionWithIP:(NSString *)ipAddress phoneDeviceId:(NSString *)phoneDeviceId {
    NSMutableData *extension = [NSMutableData data];
    
    // SEQUENCE tag
    [extension appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *extContent = [NSMutableData data];
    
    // OID for subjectAltName: 2.5.29.17
    NSData *oid = [self encodeOID:@"2.5.29.17"];
    [extContent appendData:oid];
    
    // Extension value (OCTET STRING containing GeneralNames SEQUENCE)
    NSMutableData *extValue = [NSMutableData data];
    [extValue appendBytes:(uint8_t[]){0x04} length:1]; // OCTET STRING tag
    
    // GeneralNames SEQUENCE
    NSData *generalNames = [self createGeneralNames:ipAddress phoneDeviceId:phoneDeviceId];
    
    NSData *extValueLength = [self encodeDERLength:generalNames.length];
    [extValue appendData:extValueLength];
    [extValue appendData:generalNames];
    
    [extContent appendData:extValue];
    
    // Add length
    NSData *extLength = [self encodeDERLength:extContent.length];
    [extension appendData:extLength];
    [extension appendData:extContent];
    
    return extension;
}

- (NSData *)createGeneralNames:(NSString *)ipAddress phoneDeviceId:(NSString *)phoneDeviceId {
    NSMutableData *generalNames = [NSMutableData data];
    
    // SEQUENCE tag for GeneralNames
    [generalNames appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *generalNamesContent = [NSMutableData data];
    
    // Add IP Address if provided
    if (ipAddress && ipAddress.length > 0) {
        NSData *ipData = [self encodeIPAddress:ipAddress];
        [generalNamesContent appendData:ipData];
    }
    
    // Add otherName with phone device ID if provided
    if (phoneDeviceId && phoneDeviceId.length > 0) {
        NSData *otherNameData = [self encodeOtherName:phoneDeviceId];
        [generalNamesContent appendData:otherNameData];
    }
    
    // Add length
    NSData *lengthData = [self encodeDERLength:generalNamesContent.length];
    [generalNames appendData:lengthData];
    [generalNames appendData:generalNamesContent];
    
    return generalNames;
}

- (NSData *)encodeIPAddress:(NSString *)ipAddress {
    NSMutableData *ipData = [NSMutableData data];
    
    // [7] tag for IP Address
    [ipData appendBytes:(uint8_t[]){0x87} length:1];
    
    // Parse IP address
    NSArray *octets = [ipAddress componentsSeparatedByString:@"."];
    if (octets.count == 4) {
        // Length: 4 bytes
        [ipData appendBytes:(uint8_t[]){0x04} length:1];
        
        // IP address bytes
        for (NSString *octet in octets) {
            uint8_t byte = (uint8_t)[octet intValue];
            [ipData appendBytes:&byte length:1];
        }
    }
    
    return ipData;
}

- (NSData *)encodeOtherName:(NSString *)phoneDeviceId {
    NSMutableData *otherNameData = [NSMutableData data];
    
    // [0] tag for otherName (context-specific, constructed)
    [otherNameData appendBytes:(uint8_t[]){0xA0} length:1];
    
    NSMutableData *otherNameContent = [NSMutableData data];
    
    // SEQUENCE for otherName structure
    [otherNameContent appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *seqContent = [NSMutableData data];
    
    // OID for device info: 1.3.6.1.4.1.99999.1
    NSData *oidData = [self encodeOID:@"1.3.6.1.4.1.99999.1"];
    [seqContent appendData:oidData];
    
    // [0] EXPLICIT tag wrapper for the value
    NSMutableData *valueWrapper = [NSMutableData data];
    [valueWrapper appendBytes:(uint8_t[]){0xA0} length:1];
    
    NSMutableData *valueContent = [NSMutableData data];
    
    // UTF8String with phone device ID
    [valueContent appendBytes:(uint8_t[]){0x0C} length:1];
    
    NSData *stringData = [phoneDeviceId dataUsingEncoding:NSUTF8StringEncoding];
    NSData *stringLength = [self encodeDERLength:stringData.length];
    [valueContent appendData:stringLength];
    [valueContent appendData:stringData];
    
    // Add length for [0] EXPLICIT wrapper
    NSData *valueWrapperLength = [self encodeDERLength:valueContent.length];
    [valueWrapper appendData:valueWrapperLength];
    [valueWrapper appendData:valueContent];
    
    [seqContent appendData:valueWrapper];
    
    // Add length for SEQUENCE
    NSData *seqLength = [self encodeDERLength:seqContent.length];
    [otherNameContent appendData:seqLength];
    [otherNameContent appendData:seqContent];
    
    // Add length for [0] tag
    NSData *otherNameLength = [self encodeDERLength:otherNameContent.length - 1];
    [otherNameData appendData:otherNameLength];
    [otherNameData appendData:[otherNameContent subdataWithRange:NSMakeRange(1, otherNameContent.length - 1)]];
    
    return otherNameData;
}

#pragma mark - Attributes

- (NSData *)createAttributes:(NSData *)extensionsData {
    NSMutableData *attributes = [NSMutableData data];
    
    // [0] tag for attributes (context-specific, constructed)
    [attributes appendBytes:(uint8_t[]){0xA0} length:1];
    
    NSMutableData *attributesContent = [NSMutableData data];
    
    // SEQUENCE tag
    [attributesContent appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *seqContent = [NSMutableData data];
    
    // OID for extensionRequest: 1.2.840.113549.1.9.14
    NSData *oid = [self encodeOID:@"1.2.840.113549.1.9.14"];
    [seqContent appendData:oid];
    
    // SET tag
    NSMutableData *setValue = [NSMutableData data];
    [setValue appendBytes:(uint8_t[]){0x31} length:1];
    
    NSData *setLength = [self encodeDERLength:extensionsData.length];
    [setValue appendData:setLength];
    [setValue appendData:extensionsData];
    
    [seqContent appendData:setValue];
    
    // Add length for SEQUENCE
    NSData *seqLength = [self encodeDERLength:seqContent.length];
    [attributesContent appendData:seqLength];
    [attributesContent appendData:seqContent];
    
    // Add length for [0] tag
    NSData *attributesLength = [self encodeDERLength:attributesContent.length - 1];
    [attributes appendData:attributesLength];
    [attributes appendData:[attributesContent subdataWithRange:NSMakeRange(1, attributesContent.length - 1)]];
    
    return attributes;
}

#pragma mark - CertificationRequestInfo

- (NSData *)createCertificationRequestInfo:(NSData *)subject
                                       spki:(NSData *)spki
                                 attributes:(NSData *)attributes {
    NSMutableData *certRequestInfo = [NSMutableData data];
    
    // SEQUENCE tag
    [certRequestInfo appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *certRequestInfoContent = [NSMutableData data];
    
    // Version: 0
    [certRequestInfoContent appendBytes:(uint8_t[]){0x02, 0x01, 0x00} length:3];
    
    // Subject
    [certRequestInfoContent appendData:subject];
    
    // Subject Public Key Info
    [certRequestInfoContent appendData:spki];
    
    // Attributes
    [certRequestInfoContent appendData:attributes];
    
    // Add length
    NSData *certRequestInfoLength = [self encodeDERLength:certRequestInfoContent.length];
    [certRequestInfo appendData:certRequestInfoLength];
    [certRequestInfo appendData:certRequestInfoContent];
    
    return certRequestInfo;
}

#pragma mark - Final CSR

- (NSData *)buildFinalCSR:(NSData *)certRequestInfo signature:(NSData *)signature {
    NSMutableData *csr = [NSMutableData data];
    
    // SEQUENCE tag
    [csr appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *csrContent = [NSMutableData data];
    
    // CertificationRequestInfo
    [csrContent appendData:certRequestInfo];
    
    // Signature Algorithm Identifier
    NSData *sigAlgId = [self createSignatureAlgorithmIdentifier];
    [csrContent appendData:sigAlgId];
    
    // Signature (BIT STRING)
    NSMutableData *signatureBitString = [NSMutableData data];
    [signatureBitString appendBytes:(uint8_t[]){0x03} length:1]; // BIT STRING tag
    
    NSMutableData *bitStringContent = [NSMutableData data];
    [bitStringContent appendBytes:(uint8_t[]){0x00} length:1]; // No unused bits
    [bitStringContent appendData:signature];
    
    NSData *bitStringLength = [self encodeDERLength:bitStringContent.length];
    [signatureBitString appendData:bitStringLength];
    [signatureBitString appendData:bitStringContent];
    
    [csrContent appendData:signatureBitString];
    
    // Add length
    NSData *csrLength = [self encodeDERLength:csrContent.length];
    [csr appendData:csrLength];
    [csr appendData:csrContent];
    
    return csr;
}

- (NSData *)createSignatureAlgorithmIdentifier {
    NSMutableData *sigAlgId = [NSMutableData data];
    
    // SEQUENCE tag
    [sigAlgId appendBytes:(uint8_t[]){0x30} length:1];
    
    NSMutableData *sigAlgIdContent = [NSMutableData data];
    
    // OID for ecdsa-with-SHA256: 1.2.840.10045.4.3.2
    NSData *oid = [self encodeOID:@"1.2.840.10045.4.3.2"];
    [sigAlgIdContent appendData:oid];
    
    // Add length
    NSData *sigAlgIdLength = [self encodeDERLength:sigAlgIdContent.length];
    [sigAlgId appendData:sigAlgIdLength];
    [sigAlgId appendData:sigAlgIdContent];
    
    return sigAlgId;
}

#pragma mark - Utility Methods

- (NSData *)encodeOID:(NSString *)oid {
    NSMutableData *oidData = [NSMutableData data];
    
    // OID tag
    [oidData appendBytes:(uint8_t[]){0x06} length:1];
    
    NSArray *components = [oid componentsSeparatedByString:@"."];
    NSMutableData *oidBytes = [NSMutableData data];
    
    // First two components encoded as: 40 * first + second
    NSInteger first = [components[0] integerValue];
    NSInteger second = [components[1] integerValue];
    uint8_t firstByte = (uint8_t)(40 * first + second);
    [oidBytes appendBytes:&firstByte length:1];
    
    // Remaining components
    for (NSInteger i = 2; i < components.count; i++) {
        NSInteger value = [components[i] integerValue];
        NSData *encoded = [self encodeOIDComponent:value];
        [oidBytes appendData:encoded];
    }
    
    // Add length
    uint8_t length = (uint8_t)oidBytes.length;
    [oidData appendBytes:&length length:1];
    [oidData appendData:oidBytes];
    
    return oidData;
}

- (NSData *)encodeOIDComponent:(NSInteger)value {
    NSMutableData *data = [NSMutableData data];
    
    if (value < 128) {
        uint8_t byte = (uint8_t)value;
        [data appendBytes:&byte length:1];
    } else {
        NSMutableArray *bytes = [NSMutableArray array];
        while (value > 0) {
            [bytes insertObject:@(value & 0x7F) atIndex:0];
            value >>= 7;
        }
        
        for (NSInteger i = 0; i < bytes.count; i++) {
            uint8_t byte = [bytes[i] unsignedCharValue];
            if (i < bytes.count - 1) {
                byte |= 0x80; // Set high bit for all but last byte
            }
            [data appendBytes:&byte length:1];
        }
    }
    
    return data;
}

- (NSData *)encodeDERLength:(NSUInteger)length {
    NSMutableData *data = [NSMutableData data];
    
    if (length < 128) {
        uint8_t byte = (uint8_t)length;
        [data appendBytes:&byte length:1];
    } else {
        NSMutableData *lengthBytes = [NSMutableData data];
        NSUInteger temp = length;
        while (temp > 0) {
            uint8_t byte = (uint8_t)(temp & 0xFF);
            [lengthBytes replaceBytesInRange:NSMakeRange(0, 0) withBytes:&byte length:1];
            temp >>= 8;
        }
        
        uint8_t firstByte = 0x80 | (uint8_t)lengthBytes.length;
        [data appendBytes:&firstByte length:1];
        [data appendData:lengthBytes];
    }
    
    return data;
}

- (NSString *)convertToPEM:(NSData *)derData {
    NSString *base64 = [derData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    NSMutableString *pem = [NSMutableString string];
    [pem appendString:@"-----BEGIN CERTIFICATE REQUEST-----\n"];
    [pem appendString:base64];
    if (![base64 hasSuffix:@"\n"]) {
        [pem appendString:@"\n"];
    }
    [pem appendString:@"-----END CERTIFICATE REQUEST-----\n"];
    
    return pem;
}

@end
