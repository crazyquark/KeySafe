import Foundation

public class ECDSA
{
    static public let PublicKeyTag = "r4-public-key"
    static public let PrivateKeyTag = "r4-private-key"
    
    enum CryptoCoinAddressType
    {
        case Bitcoin
        case Ripple
    }
    
    static public func generateKeyPair(privateKeyTag: String, publicKeyTag: String) -> (result:OSStatus, privateKey: SecKey?, publicKey: SecKey?) {
        var aclError: Unmanaged<CFErrorRef>?

        // OK, let's hope for the best and a not nil
        let accessControl: SecAccessControlCreateFlags = [SecAccessControlCreateFlags.TouchIDAny, SecAccessControlCreateFlags.PrivateKeyUsage]
        let privateKeyACL = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, accessControl, &aclError)
        
        if let err = aclError?.takeRetainedValue()
        {
            print("[ECDSA]Failed to create ACL: " + String(err))
            return (-1, nil, nil) // Because I got no clue
        }
        
        let publicKeyParams: [String: AnyObject] = [
            //kSecClass                as String: kSecClassKey,
            kSecAttrLabel              as String: publicKeyTag,
        ]
        
        let privateKeyParams: [String:AnyObject] = [
            //kSecClass as String: kSecClassKey,
            kSecAttrAccessControl as String: privateKeyACL!,
            kSecAttrIsPermanent as String: kCFBooleanTrue,
            kSecAttrLabel as String: privateKeyTag,
        ];
        
        
        let keyGenParams:[String:AnyObject] = [
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave as String,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateKeyParams,
            kSecPublicKeyAttrs as String: publicKeyParams,
        ];
        
        var publicKey:SecKey? = nil
        var privateKey: SecKey? = nil
        
        let ret = SecKeyGeneratePair(keyGenParams, &publicKey, &privateKey)
        
        // We need to manually save the public key because the kSecAttrIsPermanent is not allowed when using kSecAttrTokenIDSecureEnclave
        if publicKey != nil
        {
            savePublicKeyToKeychain(publicKey!, tag: publicKeyTag)
        }
        
        return (ret, privateKey, publicKey)
    }
    
    static private func endianessSwapHexString(hex: String) -> String
    {
      var hexSwapped: String = String()
      var idx = hex.endIndex

      while idx > hex.startIndex
      {
          let startIdx = idx.advancedBy(-2)
          hexSwapped += hex[startIdx..<idx]
          idx = startIdx
      }

      return hexSwapped
    }
    
    static private func pointCompressECDSAKey(x: String , y: String) -> String
    {
        let xData = NSData(hexString: x)
        let yData = NSData(hexString: y)
        
        let result = NSMutableData(length: xData.length + 1)!
        
        let firstByte = [2 + (UInt8(yData.bytes[yData.length - 1]) & 1)]
        result.replaceBytesInRange(NSRange(location: 0,length: 1), withBytes: firstByte)
        result.replaceBytesInRange(NSRange(location: 1, length: xData.length), withBytes: xData.bytes)
        
        return result.hexStringRepresentationUppercase(true)
    }
    
    /**
    * Get from keychain the saved public key and point compress it
    */
    static public func getPointCompressedPubKey(publicKeyTag: String) -> (full: String?, compressed: String?)
    {
        if let publicKey = getKeyFromKeychain(publicKeyTag, returnData: true)
        {
            //let ASN1Header = "3059301306072a8648ce3d020106082a8648ce3d030107034200".uppercaseString
            
            let uncompressedKey = (publicKey as! NSData).hexStringRepresentationUppercase(true)
            
            let x = uncompressedKey.substringWithRange(uncompressedKey.startIndex.advancedBy(2)..<uncompressedKey.startIndex.advancedBy(64 + 2))
            let y = uncompressedKey.substringWithRange(uncompressedKey.startIndex.advancedBy(64 + 2)..<uncompressedKey.endIndex)
            
            //let xSwapped = endianessSwapHexString(x)
            //let ySwapped = endianessSwapHexString(y)
            
            //let swappedUncompressedKey = "04" + xSwapped + ySwapped
            
            let pcKey = pointCompressECDSAKey(x, y: y)
            
            return (uncompressedKey, pcKey)
        }
        
        return (nil, nil)
    }
    
    /**
    * Save or update public key in the keychain
    */
    static private func savePublicKeyToKeychain(key: SecKey, tag: String)
    {
        // Dummy data to swing aroung at swift
        var dataRef :AnyObject? = nil;
        
        let searchDict =
        [
            kSecClass               as String   : kSecClassKey,
            kSecAttrLabel           as String   : tag,
            //kSecMatchLimitOne       as String   : kCFBooleanTrue,
            //kSecReturnRef           as String   : kCFBooleanTrue,
        ]
        
        var result = SecItemDelete(searchDict)
        if result == errSecSuccess
        {
            // Because I couldn't figure out how to use SecItemUpdate with a SecKey ref
            print("[ECDSA]Deleted previously saved public key")
        }
        
        // Brand spanking new!
        let newItemDict = [
            kSecClass               as String  : kSecClassKey,
            kSecAttrLabel           as String  : tag,
            kSecValueRef            as String  : key,
        ]
        
        result = SecItemAdd(newItemDict, &dataRef)
        if result == errSecSuccess
        {
            print("[ECDSA]Saved public key to keychain")
        }
    }
    
    /**
    * Loads a previously generated key pair
    */
    public static func loadKeyPair(privateKeyTag: String, publicKeyTag: String) -> (privateKey: SecKey?, publicKey: SecKey?)
    {
        let privKey: SecKey = getKeyFromKeychain(privateKeyTag) as! SecKey
        let pubKey: SecKey = getKeyFromKeychain(publicKeyTag) as! SecKey
        
        return (privKey, pubKey)
    }
    
    /**
    * Return a saved key from keychain
    */
    static public func getKeyFromKeychain(tag: String, returnData: Bool = false) -> AnyObject?
    {
        // Dummy data to swing aroung at swift
        var dataRef :AnyObject? = nil;
        
        let format: String = returnData ? kSecReturnData as String : kSecReturnRef as String
        
        let searchDict =
        [
            kSecClass               as String   : kSecClassKey,
            kSecAttrLabel           as String   : tag,
            kSecMatchLimitOne       as String   : kCFBooleanTrue,
            format                              : kCFBooleanTrue,
            
        ]
        
        let result = SecItemCopyMatching(searchDict, &dataRef)
        if result == errSecSuccess
        {
            return dataRef
        }
        
        return nil
    }
    
    /**
    * Retrieve a private key from keychain for signing purposes.
    * Requires user authtentication
    */
    static public func getPrivateKeyForSigning(tag: String) -> SecKey?
    {
        var dataRef :AnyObject? = nil;
        
        let searchDict =
        [
            kSecClass                   as String   : kSecClassKey,
            kSecAttrKeyClass            as String   : kSecAttrKeyClassPrivate,
            kSecAttrLabel               as String   : tag,
            kSecReturnRef               as String   : kCFBooleanTrue,
            kSecUseOperationPrompt      as String   : "Authenticate to sign data",
        ]
        
        let result = SecItemCopyMatching(searchDict, &dataRef)
        if result == errSecSuccess
        {
            return (dataRef as! SecKey)
        }
        
        return nil
    }

    /**
    * Signs a block of data with a given key ref
    */
    static public func signWithPrivateKey(privateKeyTag: String, hashHex: String) -> (OSStatus, signedDataHex: String?)
    {
        var ret: OSStatus = -1;
        
        if let privateKey = getPrivateKeyForSigning(PrivateKeyTag)
        {
            let data = NSData(hexString: hashHex)
            
            let signedData = NSMutableData(length: 128)! // Because nthere is never enough space (!!)
            var signedDataLength = signedData.length - 1
            
            ret = SecKeyRawSign(privateKey, .None, UnsafePointer<UInt8>(data.bytes), data.length, UnsafeMutablePointer<UInt8>(signedData.mutableBytes), &signedDataLength)
            let signedDataResultHex = signedData.hexStringRepresentationUppercase(true)
            let signedDataHex = signedDataResultHex.substringToIndex(signedDataResultHex.startIndex.advancedBy(signedDataLength * 2)) // 1 byte = 2 hex chars
            
            print("[ECDSA]signedDataHex = " + signedDataHex)
            
            return (ret, signedDataHex)
        }
        
        return (ret, nil);
    }
    
    static func generateRippleAddressFromCompressedPublicKey(ecKeyHex: String) -> String
    {
        let sha256Hash: String = SHA256.hexStringDigest(ecKeyHex)
        let ripeHash: String = RIPEMD.hexStringDigest(sha256Hash)
        
        var binaryAddr = "00" + ripeHash
        var checksum: String = SHA256.hexStringDigest(SHA256.hexStringDigest(binaryAddr) as String)
        checksum = checksum[checksum.startIndex..<checksum.startIndex.advancedBy(8)] // first 4 bytes
        
        binaryAddr += checksum
        let base58Addr =  BaseConverter.convertBase(binaryAddr, fromBase: 16, toBase: 58, forRipple: true)
        
        var padding = ""
        for var i = 0; i < binaryAddr.characters.count; i += 2
        {
            let digit = binaryAddr[binaryAddr.startIndex.advancedBy(i)..<binaryAddr.startIndex.advancedBy(i+2)]
            if digit == "00"
            {
                padding += "r"
            }
            else
            {
                break
            }
        }
        
        return padding + base58Addr
    }
    
    /**
    * As a trial run this function should generate a Bitcoin address from a full ECDSA public address
    * https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#How_to_create_Bitcoin_Address
    */
    static func generateCryptoCoinAddresses(ecKeyHex: String = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6",
        verPrefix: String = "01") -> (btcAddr: String, rippleAddr: String)
    {
        // Step 1: SHA256 hash
        let sha256Hash: String = SHA256.hexStringDigest(ecKeyHex).uppercaseString
        print("[ECDSA]sha256= " + sha256Hash)
        
        // Step 2: RIPEMD-160 hash of the SHA256 hash
        let ripemd160Hash: String = RIPEMD.hexStringDigest(sha256Hash)
        print("[ECDSA]ripemd160(sha256)= " + ripemd160Hash)
        
        // Step 3: Add network code to hash
        let ripemd160Extended = "00" + ripemd160Hash // Add network code
        print("[ECDSA]ripemd160Extended= " + ripemd160Extended)
        
        // Base58Check step 1: hash extended ripemd-160 hash
        let base58CheckSHA256: String = SHA256.hexStringDigest(ripemd160Extended).uppercaseString
        print("[ECDSA]base58CheckSHA256= " + base58CheckSHA256)
        
        // Base58Check 2: sha256 of sha256 of ripemd-160
        let base58CheckSHA256ofSHA256: String = SHA256.hexStringDigest(base58CheckSHA256).uppercaseString
        print("[ECDSA]base58CheckSHA256ofSHA256= " + base58CheckSHA256ofSHA256)
        
        // First 8 bytes are the checksum
        let checksum = base58CheckSHA256ofSHA256[base58CheckSHA256ofSHA256.startIndex..<base58CheckSHA256ofSHA256.startIndex.advancedBy(8)]
        print("[ECDSA]checksum= ", checksum)
        
        // Append checksum
        let binaryBitcoinAddr = ripemd160Extended + checksum
        print("[ECDSA]binaryBitcoinAddr=" + binaryBitcoinAddr)
        
        var leadingZeros = ""
        var leadingRs = ""
        for var i = 0; i < binaryBitcoinAddr.characters.count; i += 2
        {
            let digit = binaryBitcoinAddr[binaryBitcoinAddr.startIndex.advancedBy(i)..<binaryBitcoinAddr.startIndex.advancedBy(i+2)]
            if digit == "00"
            {
                leadingZeros += "1"
                leadingRs += "r"
            }
            else
            {
                break
            }
        }
        
        let base58BitcoinAddr = leadingZeros + BaseConverter.convertBase(binaryBitcoinAddr, fromBase: 16, toBase: 58)
        print("[ECDSA]base58BitcoinAddr= " + base58BitcoinAddr)
        
        let base58RippleAddr = leadingRs + BaseConverter.convertBase(binaryBitcoinAddr, fromBase: 16, toBase: 58, forRipple: true)
        print("[ECDSA]base58RippleAddr= " + base58RippleAddr)
        
        return (base58BitcoinAddr, base58RippleAddr)
    }
}
