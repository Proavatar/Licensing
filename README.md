# Licensing

This repository holds a Swift Package to add licensing functionality to a Swift project using a asymmetric security key-pairs comprising a RSA private and public key.

In the method implemented in this package, licenses are granted based on the bundle identifier as specified for the application. By convention the bundle identifier is specified it using the reverse domain name notation or reverse-DNS. For example, if a company making the app "MyApp" has the domain name example.com, they could use the reverse-DNS string `com.example.MyApp` as an identifier for the app.

With respect to licensing, there is the option to obtain a license for a specific app or for all apps by the company. In the latter case, the used bundle identifier used to create the license is set to the reverse-DNS string of the domain, so `com.example` in the example.

The package implements the following functionality:
* Generating a new RSA asymmetric key-pair.
* Generate a license key by supplying the private key and the bundle identifier.
* Convert a Base64 representation of a security key into its binary representation.
* Validate a license key by supplying the public key and the bundle identifier.

For a complete reference, download the document "[Licensing SDK](https://docs.google.com/document/d/1lQ_W0G891qJgnb63-4g72k95IIa5zuBn3TznHAQkiiI/export?format=pdf)"

