import Foundation

/// Service account key structure from Google Cloud Console JSON key file
public struct ServiceAccountKey: Codable {
    public let type: String
    public let projectId: String
    public let privateKeyId: String
    public let privateKey: String
    public let clientEmail: String
    public let clientId: String
    public let authUri: String
    public let tokenUri: String
    public let authProviderX509CertUrl: String
    public let clientX509CertUrl: String
    public let universeDomain: String?

    enum CodingKeys: String, CodingKey {
        case type
        case projectId = "project_id"
        case privateKeyId = "private_key_id"
        case privateKey = "private_key"
        case clientEmail = "client_email"
        case clientId = "client_id"
        case authUri = "auth_uri"
        case tokenUri = "token_uri"
        case authProviderX509CertUrl = "auth_provider_x509_cert_url"
        case clientX509CertUrl = "client_x509_cert_url"
        case universeDomain = "universe_domain"
    }

    public init(type: String, projectId: String, privateKeyId: String, privateKey: String, clientEmail: String, clientId: String, authUri: String, tokenUri: String, authProviderX509CertUrl: String, clientX509CertUrl: String, universeDomain: String? = nil) {
        self.type = type
        self.projectId = projectId
        self.privateKeyId = privateKeyId
        self.privateKey = privateKey
        self.clientEmail = clientEmail
        self.clientId = clientId
        self.authUri = authUri
        self.tokenUri = tokenUri
        self.authProviderX509CertUrl = authProviderX509CertUrl
        self.clientX509CertUrl = clientX509CertUrl
        self.universeDomain = universeDomain
    }
}
