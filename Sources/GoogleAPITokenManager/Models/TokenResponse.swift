import Foundation

struct TokenResponse: Codable {
    let accessToken: String
    let refreshToken: String?
    let expiresIn: TimeInterval?
    let tokenType: String?
    let scope: String?
    let idToken: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
        case scope
        case idToken = "id_token"
    }
}

