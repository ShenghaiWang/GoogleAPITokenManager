import Foundation
import JWTKit

/// JWT Generator for service account authentication
class JWTGenerator {
    static func generateJWT(
        serviceAccountKey: ServiceAccountKey,
        scopes: [String],
        impersonationUser: String? = nil
    ) throws -> String {
        let now = Date()
        let expiration = now.addingTimeInterval(3600) // 1 hour

        let payload = GoogleServiceAccountPayload(
            iss: IssuerClaim(value: serviceAccountKey.clientEmail),
            scope: ScopeClaim(value: scopes.joined(separator: " ")),
            aud: AudienceClaim(value: [serviceAccountKey.tokenUri]),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: impersonationUser.map { SubjectClaim(value: $0) }
        )

        // Create JWT signers
        let signers = JWTSigners()

        // Parse and add RSA private key
        let privateKey = try parsePrivateKey(serviceAccountKey.privateKey)
        signers.use(.rs256(key: privateKey), kid: JWKIdentifier(string: "service-account"))

        // Sign the JWT
        return try signers.sign(payload, kid: JWKIdentifier(string: "service-account"))
    }

    private static func parsePrivateKey(_ privateKeyString: String) throws -> RSAKey {
        // JWTKit expects PEM format, so we reconstruct it if headers are missing
        let cleanedKey = privateKeyString
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: " ", with: "")

        let pemKey: String
        if cleanedKey.contains("-----BEGIN") {
            // Already in PEM format
            pemKey = privateKeyString
        } else {
            // Add PEM headers
            let base64Key = cleanedKey
            pemKey = """
            -----BEGIN PRIVATE KEY-----
            \(base64Key.chunked(into: 64).joined(separator: "\n"))
            -----END PRIVATE KEY-----
            """
        }

        do {
            return try RSAKey.private(pem: pemKey.data(using: .utf8)!)
        } catch {
            throw Error.authenticationFailed("Failed to parse RSA private key: \(error.localizedDescription)")
        }
    }
}

/// Convenience extension for chunking strings (used for PEM formatting)
extension String {
    func chunked(into size: Int) -> [String] {
        return stride(from: 0, to: count, by: size).map {
            let start = index(startIndex, offsetBy: $0)
            let end = index(start, offsetBy: min(size, count - $0))
            return String(self[start..<end])
        }
    }
}
