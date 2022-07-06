// ---------------------------------------------------------------------------------------------
//  Licensing.swift
// ---------------------------------------------------------------------------------------------

import Foundation
import Security

// ---------------------------------------------------------------------------------------------
public struct KeyPair
{
    public var privateKey : String
    public var publicKey  : String
}

// ---------------------------------------------------------------------------------------------
public func generateLicenseKey( privateKey : String, bundleId : String) -> String?
{
    guard let privateSecKey = getPrivateSecKey( privateKey )
    else
    {
        return nil
    }
    
    let data = bundleId.data(using: .utf8)! as CFData

    guard let licenseKey = signData( privateSecKey : privateSecKey, data: data )
    else
    {
        return nil
    }
    return licenseKey
}

// ---------------------------------------------------------------------------------------------
public func signData( privateSecKey: SecKey, data: CFData ) -> String?
{
    let algorithm : SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
    var error: Unmanaged<CFError>?
    
    guard let signature = SecKeyCreateSignature( privateSecKey, algorithm, data, &error ) as Data?
    else
    {
        print( error!.takeRetainedValue() )
        return nil
    }
    return signature.base64EncodedString()
}

// ---------------------------------------------------------------------------------------------
public func getPublicSecKey(_ publicKey: String ) -> SecKey?
{
    return getSecKey( base64KeyString: publicKey, keyClass: kSecAttrKeyClassPublic )
}

// ---------------------------------------------------------------------------------------------
public func getPrivateSecKey(_ privateKey: String ) -> SecKey?
{
    return getSecKey( base64KeyString: privateKey, keyClass: kSecAttrKeyClassPrivate )
}

// ---------------------------------------------------------------------------------------------
public func getSecKey( base64KeyString: String, keyClass: CFString ) -> SecKey?
{
    let keyData = Data( base64Encoded: base64KeyString )! as CFData

    let attributes = [ kSecAttrKeyType       : kSecAttrKeyTypeRSA,
                       kSecAttrKeyClass      : keyClass,
                       kSecAttrKeySizeInBits : 2048 ] as CFDictionary

    var error: Unmanaged<CFError>?
    
    guard let key = SecKeyCreateWithData( keyData, attributes, &error )
    else
    {
        print( error!.takeRetainedValue() )
        return nil
    }

    return key
}

// ---------------------------------------------------------------------------------------------
public func validateLicenseKey( publicKey : String, licenseKey: String, bundleId: String ) -> Bool
{
    guard let appBundleId = Bundle.main.bundleIdentifier else
    {
        print( "WARNING: no bundle identifier specified." )
        return false
    }
    
    if !appBundleId.contains( bundleId )
    {
        print( "WARNING: wrong bundle identifier in license file." )
        return false
    }
    
    guard let key = getPublicSecKey( publicKey )
    else
    {
        return false
    }
    
    let algorithm : SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
    let signedData = bundleId.data( using: .utf8 )! as CFData
    
    guard let signatureData = Data( base64Encoded: licenseKey ) as CFData? else
    {
        print("ERROR: The signature isn't a base64 string!")
        return false
    }

    var error: Unmanaged<CFError>?
    
    if SecKeyVerifySignature( key, algorithm, signedData, signatureData, &error )
    {
        return true
    }
    
    print( error!.takeRetainedValue() )
    return false
}

// ---------------------------------------------------------------------------------------------
func encodeSecKey(_ secKey: SecKey ) -> String?
{
    var error: Unmanaged<CFError>?

    guard let keyData = SecKeyCopyExternalRepresentation( secKey, &error )
    else
    {
        print( error!.takeRetainedValue() )
        return nil
    }
        
    return (keyData as NSData).base64EncodedString()
}

// ---------------------------------------------------------------------------------------------
func generateNewAsymetricKeyPair() -> KeyPair?
{
    let attributes = [ kSecAttrKeyType       : kSecAttrKeyTypeRSA,
                       kSecAttrKeySizeInBits : 2048 ] as CFDictionary

    var error: Unmanaged<CFError>?
    
    guard let privateSecKey = SecKeyCreateRandomKey( attributes, &error )
    else
    {
        print( error!.takeRetainedValue() )
        return nil
    }
    
    guard let publicSecKey = SecKeyCopyPublicKey( privateSecKey )
    else
    {
        return nil
    }
    
    if let privateKey = encodeSecKey( privateSecKey ),
       let publicKey  = encodeSecKey( publicSecKey  )
    {
        return KeyPair( privateKey: privateKey, publicKey: publicKey )
    }
    
    return nil
}

// ---------------------------------------------------------------------------------------------
public var hasValidLicense : Bool = false
// ---------------------------------------------------------------------------------------------


