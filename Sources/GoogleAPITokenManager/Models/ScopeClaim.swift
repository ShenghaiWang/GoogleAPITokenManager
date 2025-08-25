import JWTKit

/// Custom claim for OAuth2 scopes
struct ScopeClaim: JWTClaim, Equatable {
    var value: String

    init(value: String) {
        self.value = value
    }
}
