import Foundation
import Security
import CommonCrypto

/// JWT Generator for service account authentication
internal class JWTGenerator {
    static func generateJWT(
        serviceAccountKey: ServiceAccountKey,
        scopes: [String],
        impersonationUser: String? = nil
    ) throws -> String {
        let now = Int(Date().timeIntervalSince1970)
        let expiration = now + 3600 // 1 hour
        
        let claims = JWTClaims(
            iss: serviceAccountKey.clientEmail,
            scope: scopes.joined(separator: " "),
            aud: serviceAccountKey.tokenUri,
            exp: expiration,
            iat: now,
            sub: impersonationUser
        )
        
        // Create JWT header
        let header = JWTHeader(alg: "RS256", typ: "JWT")
        let headerData = try JSONEncoder().encode(header)
        let headerBase64 = headerData.base64URLEncodedString()
        
        // Create JWT payload
        let payloadData = try JSONEncoder().encode(claims)
        let payloadBase64 = payloadData.base64URLEncodedString()
        
        // Create signature
        let signingInput = "\(headerBase64).\(payloadBase64)"
        let signature = try signWithRSA(data: signingInput, privateKey: serviceAccountKey.privateKey)
        let signatureBase64 = signature.base64URLEncodedString()
        
        return "\(signingInput).\(signatureBase64)"
    }
    
    private static func signWithRSA(data: String, privateKey: String) throws -> Data {
        // Parse the private key
        let secKey = try parsePrivateKey(privateKey)
        
        // Create signature
        let dataToSign = data.data(using: .utf8)!
        var error: Unmanaged<CFError>?
        
        guard let signature = SecKeyCreateSignature(
            secKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            dataToSign as CFData,
            &error
        ) else {
            if let error = error?.takeRetainedValue() {
                throw Error.authenticationFailed("Failed to sign JWT: \(error)")
            }
            throw Error.authenticationFailed("Failed to sign JWT: Unknown error")
        }
        
        return signature as Data
    }
    
    private static func parsePrivateKey(_ privateKeyString: String) throws -> SecKey {
        // Remove PEM headers and whitespace
        let cleanKey = privateKeyString
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: " ", with: "")
        
        guard let keyData = Data(base64Encoded: cleanKey) else {
            throw Error.authenticationFailed("Invalid private key format - base64 decoding failed")
        }
        
        // Try using SecItemImport which is more robust for PKCS#8 keys
        var importParams = SecItemImportExportKeyParameters()
        importParams.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
        importParams.flags = SecKeyImportExportFlags(rawValue: 0)
        importParams.passphrase = nil
        importParams.alertTitle = nil
        importParams.alertPrompt = nil
        importParams.accessRef = nil
        importParams.keyUsage = nil
        importParams.keyAttributes = nil
        
        var outItems: CFArray?
        let importStatus = SecItemImport(
            keyData as CFData,
            nil, // filename
            nil, // inputFormat (let system determine)
            nil, // itemType (let system determine)
            SecItemImportExportFlags(rawValue: 0),
            &importParams,
            nil, // keychain (use default)
            &outItems
        )
        
        if importStatus == errSecSuccess, let items = outItems as? [Any], !items.isEmpty {
            // Successfully imported, now extract the SecKey
            if let firstItem = items.first {
                // Check if it's a SecKey by comparing CFTypeIDs
                if CFGetTypeID(firstItem as CFTypeRef) == SecKeyGetTypeID() {
                    return (firstItem as! SecKey)
                }
            }
        }
        
        // If SecItemImport fails, fall back to SecKeyCreateWithData
        var error: Unmanaged<CFError>?
        
        // Try with minimal attributes
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        
        if let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) {
            return secKey
        }
        
        // If both methods fail, provide detailed error information
        var errorMessage = "Failed to create private key using both SecItemImport (status: \(importStatus)) and SecKeyCreateWithData"
        
        if let error = error?.takeRetainedValue() {
            let errorDescription = CFErrorCopyDescription(error)
            let errorString = errorDescription as String? ?? "Unknown CFError"
            errorMessage += ": \(errorString)"
        }
        
        let keyDataHex = keyData.prefix(20).map { String(format: "%02x", $0) }.joined()
        errorMessage += ". Key data length: \(keyData.count) bytes, starts with: \(keyDataHex)..."
        
        throw Error.authenticationFailed(errorMessage)
    }
}
