import Foundation

/// JWT Claims for Google OAuth2 service account authentication
internal struct JWTClaims: Codable {
    let iss: String // Service account email
    let scope: String // Space-delimited scopes
    let aud: String // Token endpoint URL
    let exp: Int // Expiration timestamp
    let iat: Int // Issued at timestamp
    let sub: String? // Impersonation user email (optional)

    init(iss: String, scope: String, aud: String, exp: Int, iat: Int, sub: String? = nil) {
        self.iss = iss
        self.scope = scope
        self.aud = aud
        self.exp = exp
        self.iat = iat
        self.sub = sub
    }
}
