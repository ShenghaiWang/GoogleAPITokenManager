import Foundation

public actor APIKeyTokenManager: TokenManager {
    private var apiKey: String

    public init(apiKey: String) {
        self.apiKey = apiKey
    }

    public func getAccessToken() async throws -> String {
        apiKey
    }

    public func refreshToken() async throws -> String {
        throw Error.authenticationFailed("API key authentication does not support token refresh")
    }

    public func isAuthenticated() async -> Bool {
        !apiKey.isEmpty
    }

    public func authenticate(scopes: [String]) async throws -> AuthResult {
        .init(accessToken: apiKey)
    }

    public func clearTokens() async throws {
        apiKey = ""
    }
}
