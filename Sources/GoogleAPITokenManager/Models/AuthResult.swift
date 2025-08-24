import Foundation

/// Result of authentication flow
public struct AuthResult {
    public let accessToken: String
    public let refreshToken: String?
    public let expiresIn: TimeInterval?
    public let tokenType: String
    public let scope: String?

    public init(accessToken: String, refreshToken: String? = nil, expiresIn: TimeInterval? = nil, tokenType: String = "Bearer", scope: String? = nil) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.tokenType = tokenType
        self.scope = scope
    }
}
