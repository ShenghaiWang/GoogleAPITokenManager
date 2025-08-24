import Foundation

/// JWT Header structure
struct JWTHeader: Codable {
    let alg: String
    let typ: String
}

