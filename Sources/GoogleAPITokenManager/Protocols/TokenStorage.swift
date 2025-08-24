import Foundation

public protocol TokenStorage: Actor {
    func storeTokens(accessToken: String, refreshToken: String?, expiresIn: TimeInterval?) throws
    func getAccessToken() throws -> String?
    func getRefreshToken() throws -> String?
    func isTokenExpired() throws -> Bool
    func clearTokens() throws
}
