import Foundation

public actor APIKeyTokenManager: TokenManager {
    private let apiKey: String

    public init(apiKey: String) {
        self.apiKey = apiKey
    }

    public func getAccessToken() async throws -> String {
        // For API key usage, we don't use access tokens
        // The HTTPClient will handle API key authentication
        throw Error.authenticationFailed("API key authentication does not use access tokens")
    }

    public func refreshToken() async throws -> String {
        throw Error.authenticationFailed("API key authentication does not support token refresh")
    }

    public func isAuthenticated() async -> Bool {
        !apiKey.isEmpty
    }

    public func authenticate(scopes: [String]) async throws -> AuthResult {
        throw Error.authenticationFailed("API key authentication does not support OAuth2 flow")
    }

    public func clearTokens() async throws {
        // No tokens to clear for API key authentication
    }
}
