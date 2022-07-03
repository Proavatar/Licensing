//
//  Licensing.swift
//
//  Created by Fred Dijkstra on 22/06/2022.
//

import Foundation
import Security

let publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqY4iWzN7ICR69rJCWiw1l7FwUjUR76wzXIp1A0J63MZbZULfrftJoAqCGXzzVlg7lawLhUCSz/YjvDOsFDnN+19ef2yuQFwjvB7Wb/qDfqpEIv9bG0u5VUOYGQbpuBCr3PBNjme1MzLIA1UcXpRCoHaH+ddyKhHwWybCwbakad4EeUqPwYyXsIKt0xxxllcUnKeKtLU9ZAikLN7zNerwcW0jrO0PuKpVQ1ZtRH5Oxf3EVmi+XdxuZWdSwOteDX9+Pj0RvCFrSZdRq+S8H/fS7GzgouqBU0y0xWzq4p65UJDVT0i8pNHZXE2wz1mi9EVZoLj/ki/HPPL12JFOmNPHtQIDAQAB"

func getPublicKey(_ base64PublicKeyString: String) throws -> SecKey
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

func validateLicense(license:License, publicKey: SecKey) -> Bool
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
    let userName:String
    let licenseKey:String
    
    public init(userName: String, licenseKey: String)
    {
        self.userName = userName
        self.licenseKey = licenseKey
    }
}

var hasValidLicense : Bool = false
