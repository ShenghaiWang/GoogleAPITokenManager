import Foundation
import JWTKit

/// JWT Payload structure for Google Service Account authentication
struct GoogleServiceAccountPayload: JWTPayload {
    let iss: IssuerClaim      // Service account email
    let scope: ScopeClaim     // Requested scopes
    let aud: AudienceClaim    // Token URI (usually Google's token endpoint)
    let exp: ExpirationClaim  // Expiration time
    let iat: IssuedAtClaim    // Issued at time
    let sub: SubjectClaim?    // Subject (for domain-wide delegation)

    func verify(using signer: JWTSigner) throws {
        try exp.verifyNotExpired()
    }
}
