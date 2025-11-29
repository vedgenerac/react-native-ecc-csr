#import "EccCsrGenerator.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation EccCsrGenerator

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(generateCSR:(NSString *)commonName
                  serialNumber:(NSString *)serialNumber
                  country:(NSString *)country
                  state:(NSString *)state
                  locality:(NSString *)locality
                  organization:(NSString *)organization
                  organizationalUnit:(NSString *)organizationalUnit
                  ipAddress:(NSString *)ipAddress
                  deviceInfo:(NSString *)deviceInfo
                  curve:(NSString *)curve
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        // Determine key size based on curve
        int keySize;
        if ([curve isEqualToString:@"P-256"]) {
            keySize = 256;
        } else if ([curve isEqualToString:@"P-384"]) {
            keySize = 384;
        } else if ([curve isEqualToString:@"P-521"]) {
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
        NSData *extensionsData = [self createExtensions:ipAddress deviceInfo:deviceInfo];
        
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
    // Parse DN string and create ASN.1 structure
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
    NSData *ec
