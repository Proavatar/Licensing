# Licensing SDKs

When creating an SDK that is to be offered commercially, a method that is often used is to place the SDK with limited functionality on a public repository for anybody to download and add it to their application project. The full functionality is then only available for those who have purchased a license.

This repository holds a Swift Package to add such licensing functionality to your SDK.

In the method implemented in this package, licenses are granted based on the bundle identifier as specified for the application in which the SDK is to be used.

The package implements the following main functionality:
* Generating a new RSA asymmetric key-pair.
* Generate a license key by supplying the private key and the bundle identifier.
* Create and write a license file.
* Validate a license key by supplying the public key and the bundle identifier.

For a complete reference and detailed design description, download the document "[Licensing SDKs](https://docs.google.com/document/d/1lQ_W0G891qJgnb63-4g72k95IIa5zuBn3TznHAQkiiI/preview)"

