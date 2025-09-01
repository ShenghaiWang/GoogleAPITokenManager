import Foundation

/// PKCE (Proof Key for Code Exchange) parameters for enhanced OAuth2 security
public struct PKCEParameters: Sendable {
    public let codeVerifier: String
    public let codeChallenge: String
    public let codeChallengeMethod: String
    public let state: String
    
    public init() {
        self.codeVerifier = Self.generateCodeVerifier()
        self.codeChallenge = Self.generateCodeChallenge(from: codeVerifier)
        self.codeChallengeMethod = "S256"
        self.state = UUID().uuidString
    }
    
    public init(codeVerifier: String, state: String) {
        self.codeVerifier = codeVerifier
        self.codeChallenge = Self.generateCodeChallenge(from: codeVerifier)
        self.codeChallengeMethod = "S256"
        self.state = state
    }
    
    private static func generateCodeVerifier() -> String {
        // Use secure random bytes for better entropy
        let randomData = CryptoUtils.randomBytes(count: 96) // 96 bytes = 128 base64url chars
        return randomData.base64URLEncodedString().prefix(128).description
    }
    
    private static func generateCodeChallenge(from verifier: String) -> String {
        let data = Data(verifier.utf8)
        let hash = CryptoUtils.sha256Hash(of: data)
        return hash.base64URLEncodedString()
    }
}

