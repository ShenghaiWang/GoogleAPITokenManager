import Foundation

/// Protocol for OAuth2 token management
public protocol TokenManager: Actor {
    /// Get a valid access token, refreshing if necessary
    func getAccessToken() async throws -> String

    /// Refresh the access token using the refresh token
    func refreshToken() async throws -> String

    /// Check if the user is currently authenticated
    func isAuthenticated() async -> Bool

    /// Initiate the OAuth2 authentication flow
    func authenticate(scopes: [String]) async throws -> AuthResult

    /// Clear stored tokens (logout)
    func clearTokens() async throws
}
