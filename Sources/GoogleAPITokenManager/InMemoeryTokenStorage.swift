import Foundation

/// Secure token storage using Keychain
public actor InMemoeryTokenStorage: TokenStorage {
    private var accessToken: String?
    private var refreshToken: String?
    private var expiresIn: TimeInterval?

    public func storeTokens(accessToken: String, refreshToken: String?, expiresIn: TimeInterval?) throws {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
    }

    public func getAccessToken() throws -> String? {
        accessToken
    }

    public func getRefreshToken() throws -> String? {
        refreshToken
    }

    public func isTokenExpired() throws -> Bool {
        guard let expiresIn else {
            return true // If no expiration info, consider expired
        }

        let expirationDate = Date(timeIntervalSince1970: expiresIn)
        return Date() >= expirationDate.addingTimeInterval(-300) // 5 minute buffer
    }

    public func clearTokens() throws {
        accessToken = nil
        refreshToken = nil
        expiresIn = nil
    }
}

