import Foundation

public enum Error: Swift.Error {
    case authenticationFailed(String)
    case tokenExpired
    case invalidToken
    case decodingError(Swift.Error)
    case invalidResponse(String)
    case badRequest(String)
    case accessDenied(String)
    case notFound(String)
    case rateLimitExceeded(retryAfter: TimeInterval)
    case apiError(code: Int, message: String, details: String?)
    case networkError(Swift.Error)
}
