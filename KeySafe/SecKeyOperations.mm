//
//  SecKeyOperations.m
//  KeySafe
//
//  Created by Cristian Sandu on 9/24/15.
//  Copyright © 2015 Cristian Sandu. All rights reserved.
//

#import "SecKeyOperations.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <NSData+FastHex/NSData+FastHex.h>

#include <OpenSSL/ec.h>
#include <OpenSSL/hmac.h>
#include <OpenSSL/ecdsa.h>
#include <OpenSSL/err.h>

@implementation SecKeyOperations

+ (void) generateKeyWithPrivateKeyTag: (NSString*) privateKeyTag andPublicKeyTag: (NSString*) publicKeyTag
{
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject;
    
    // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);
    
    // Create parameters dictionary for key generation.
    NSDictionary *parameters = @{
                                 (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                                 (__bridge id)kSecAttrKeySizeInBits: @256,
                                 (__bridge id)kSecPublicKeyAttrs: @{
                                         (__bridge id)kSecAttrLabel: publicKeyTag,
                                         },
                                 (__bridge id)kSecPrivateKeyAttrs: @{
                                         (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                                         (__bridge id)kSecAttrIsPermanent: @YES,
                                         (__bridge id)kSecAttrLabel: privateKeyTag,
                                         },
                                 };
    
    //dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Generate key pair.
        SecKeyRef publicKey, privateKey;
        OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
        //NSString *errorString = [self keychainErrorToString:status];
        //NSString *message = [NSString stringWithFormat:@"Key generation: %@", errorString];
        //[self printMessage:message inTextView:self.textView];
        
        if (status == errSecSuccess) {
            // In your own code, here is where you'd store/use the keys.
            
            CFRelease(privateKey);
            CFRelease(publicKey);
        }
    //});
    
}

+ (void) signUsingPrivateKeyWithTag: (NSString*) tag
{
    // Query private key object from the keychain.
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                            (__bridge id)kSecAttrLabel: tag,
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecUseOperationPrompt: @"Authenticate to sign data"
                            };
    
    //dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Retrieve the key from the keychain.  No authentication is needed at this point.
        SecKeyRef privateKey;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);
        
        if (status == errSecSuccess) {
            // Sign the data in the digest/digestLength memory block.
            uint8_t signature[128];
            size_t signatureLength = sizeof(signature);
            uint8_t digestData[16];
            size_t digestLength = sizeof(digestData);
            status = SecKeyRawSign(privateKey, kSecPaddingPKCS1, digestData, digestLength, signature, &signatureLength);
            
            //NSString *errorString = [self keychainErrorToString:status];
            //NSString *message = [NSString stringWithFormat:@"Key usage: %@", errorString];
            //[self printMessage:message inTextView:self.textView];
            
            if (status == errSecSuccess) {
                // In your own code, here is where you'd continue with the signature of the digest.
            }
            
            CFRelease(privateKey);
        }
        else {
            //NSString *message = [NSString stringWithFormat:@"Key not found: %@",[self keychainErrorToString:status]];
            
            //[self printMessage:message inTextView:self.textView];
        }
    //});
}

+ (void*) makeECDSAPublicKey:(NSString *)keyDataHex
{
    NSMutableData* keyData = [NSMutableData dataWithHexString: keyDataHex];
    unsigned char* keyDataArray = (unsigned char*)[keyData mutableBytes];

    
    // Build key
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    
    // Load key data
    EC_KEY* ret = o2i_ECPublicKey(&key, const_cast<const unsigned char**>(&keyDataArray), keyData.length);
    
    return ret;
}

+ (OSStatus) verifySignature:(NSString *)keyDataHex signedDataHex:(NSString *)signature hash:(NSString *)hash
{
    EC_KEY* key = (EC_KEY*)[self makeECDSAPublicKey:keyDataHex];
    
    if (!key)
    {
        long err = ERR_get_error();
        char buf[80];
        ERR_error_string(err, buf);
        
        return errSecParam;
    }
    
    // Process signature data; it seems that our signature is canonical:
    // <30> <len> [ <20> <lenR> <R> ] [ <02> <lenS> <S> ]
    NSMutableData* signatureData = [NSMutableData dataWithHexString: signature];
    unsigned char* signatureArray = (unsigned char*)[signatureData mutableBytes];
    
    // Data conversions
    NSMutableData* hashData = [NSMutableData dataWithHexString: hash];
    unsigned char* hashArray = (unsigned char*)[hashData mutableBytes];
    
    int ret = ECDSA_verify(0, hashArray, int(hashData.length), static_cast<const unsigned char*>(signatureArray), int(signatureData.length), key);
    
    return ret;
}

@end


