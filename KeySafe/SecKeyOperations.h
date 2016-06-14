//
//  SecKeyOperations.h
//  KeySafe
//
//  Created by Cristian Sandu on 9/24/15.
//  Copyright © 2015 Cristian Sandu. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 * This class is for reference only, code is not used
 */
@interface SecKeyOperations : NSObject

+ (void) generateKeyWithPrivateKeyTag: (NSString*) privateKeyTag andPublicKeyTag: (NSString*) publicKeyTag;
+ (void) signUsingPrivateKeyWithTag: (NSString*) tag;

// I don't want to include OpenSSL here so let's make the return void*
+ (void*) makeECDSAPublicKey: (NSString*) keyDataHex;
+ (OSStatus) verifySignature: (NSString*) keyDataHex signedDataHex: (NSString*) signature hash: (NSString*) hash;


@end
