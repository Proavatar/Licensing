//
//  Licensing.swift
//
//  Created by Fred Dijkstra on 22/06/2022.
//

import Foundation
import Security

public func getPublicKey(_ base64PublicKeyString: String) throws -> SecKey
{
    let data = Data(base64Encoded: base64PublicKeyString, options: [])!

    let options: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                  kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                  kSecAttrKeySizeInBits as String: 2048]

    var error: Unmanaged<CFError>?
    guard let publicKey = SecKeyCreateWithData(
        data as CFData,
        options as CFDictionary,
        &error
    ) else {
        throw error!.takeRetainedValue() as Error
    }

    return publicKey
}

public func validateLicense(license:License, publicKey: SecKey) -> Bool
{
    let message = license.userName.data(using: .utf8)! as CFData
    
    guard let signatureData = Data(base64Encoded: license.licenseKey) as CFData? else
    {
        print("The signature isn't a base64 string!")
        return false
    }

    let algorithm : SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
    
    var error: Unmanaged<CFError>?
    if SecKeyVerifySignature(
        publicKey,
        algorithm,
        message,
        signatureData,
        &error)
    {
        return true
    }
    else
    {
        if let error = error
        {
            print(error.takeRetainedValue())
        }
        return false
    }
}

public class License
{
    public let userName:String
    public let licenseKey:String
    
    public init(userName: String, licenseKey: String)
    {
        self.userName = userName
        self.licenseKey = licenseKey
    }
}

public var hasValidLicense : Bool = false

