import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Service Account Token Manager for server-to-server authentication
public actor ServiceAccountTokenManager: TokenManager {
    private let serviceAccountKey: ServiceAccountKey
    private let httpClient: any HTTPClient
    private let tokenStorage: (any TokenStorage)?
    private var impersonationUser: String?
    private let tokenRefreshQueue = DispatchQueue(label: "com.googleapitokenmanager.token-refresh", qos: .userInitiated)
    private var currentRefreshTask: Task<String, Swift.Error>?
    private let scopes: [String]

    public init(serviceAccountKey: ServiceAccountKey,
                httpClient: any HTTPClient,
                tokenStorage: (any TokenStorage)?,
                scopes: [String]) {
        self.serviceAccountKey = serviceAccountKey
        self.httpClient = httpClient
        self.tokenStorage = tokenStorage
        self.scopes = scopes
    }

    /// Initialize with service account key file path
    public init(serviceAccountKeyPath: String,
                httpClient: any HTTPClient,
                tokenStorage: (any TokenStorage)?,
                scopes: [String]) throws {
        let url = URL(fileURLWithPath: serviceAccountKeyPath)
        let data = try Data(contentsOf: url)
        let key = try JSONDecoder().decode(ServiceAccountKey.self, from: data)
        self.init(serviceAccountKey: key,
                  httpClient: httpClient,
                  tokenStorage: tokenStorage,
                  scopes: scopes)
    }

    /// Set user email for domain-wide delegation
    public func setImpersonationUser(_ email: String?) {
        self.impersonationUser = email
    }

    /// Clear impersonation user (return to service account identity)
    public func clearImpersonationUser() {
        self.impersonationUser = nil
    }

    /// Get current impersonation user
    public var currentImpersonationUser: String? {
        return impersonationUser
    }

    public func isAuthenticated() async -> Bool {
        // Service accounts don't store long-lived tokens, they generate them on demand
        true
    }

    public func getAccessToken() async throws -> String {
        // If keychain is disabled (server-side), always generate fresh tokens
        guard let tokenStorage = tokenStorage else {
            return try await performTokenRefresh()
        }

        // Check if we have a valid cached token
        if let accessToken = try await tokenStorage.getAccessToken(),
           await !(try tokenStorage.isTokenExpired()) {
            return accessToken
        }

        // Handle concurrent token refresh requests
        if let existingTask = currentRefreshTask {
            return try await existingTask.value
        }

        // Create new refresh task
        let refreshTask = Task<String, Swift.Error> {
            defer { currentRefreshTask = nil }
            return try await performTokenRefresh()
        }

        currentRefreshTask = refreshTask
        return try await refreshTask.value
    }

    private func performTokenRefresh() async throws -> String {
        // Double-check if token is still expired (another task might have refreshed it)
        if let tokenStorage = tokenStorage,
           let accessToken = try await tokenStorage.getAccessToken(),
           await !(try tokenStorage.isTokenExpired()) {
            return accessToken
        }

        // Generate JWT
        let jwt = try JWTGenerator.generateJWT(
            serviceAccountKey: serviceAccountKey,
            scopes: scopes,
            impersonationUser: impersonationUser
        )

        // Exchange JWT for access token
        let parameters = [
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt
        ]

        let body = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
            .data(using: .utf8)!

        let request = HTTPRequest(
            method: .POST,
            url: URL(string: serviceAccountKey.tokenUri)!,
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: body
        )

        let response: TokenResponse = try await httpClient.execute(request)

        // Cache the token only if keychain is enabled
        if let tokenStorage = tokenStorage {
            try await tokenStorage.storeTokens(
                accessToken: response.accessToken,
                refreshToken: nil, // Service accounts don't use refresh tokens
                expiresIn: response.expiresIn
            )
        }

        return response.accessToken
    }

    public func refreshToken() async throws -> String {
        // Force refresh by clearing current token and generating new one
        try await tokenStorage?.clearTokens()
        return try await performTokenRefresh()
    }

    public func authenticate(scopes: [String]) async throws -> AuthResult {
        let accessToken = try await getAccessToken()
        return AuthResult(
            accessToken: accessToken,
            refreshToken: nil,
            expiresIn: 3600, // Service account tokens typically expire in 1 hour
            tokenType: "Bearer",
            scope: scopes.joined(separator: " ")
        )
    }

    public func clearTokens() async throws {
        try await tokenStorage?.clearTokens()
    }

    /// Load service account from file
    public static func loadFromFile(_ path: String,
                                    httpClient: any HTTPClient,
                                    tokenStorage: (any TokenStorage)?,
                                    scopes: [String]) throws -> ServiceAccountTokenManager {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        let key = try JSONDecoder().decode(ServiceAccountKey.self, from: data)
        return ServiceAccountTokenManager(serviceAccountKey: key,
                                          httpClient: httpClient,
                                          tokenStorage: tokenStorage,
                                          scopes: scopes)
    }

    /// Load service account from environment variable GOOGLE_APPLICATION_CREDENTIALS
    public static func loadFromEnvironment(httpClient: any HTTPClient,
                                           tokenStorage: (any TokenStorage)?,
                                           scopes: [String]) throws -> ServiceAccountTokenManager {
        guard let path = ProcessInfo.processInfo.environment["GOOGLE_APPLICATION_CREDENTIALS"] else {
            throw Error.authenticationFailed("GOOGLE_APPLICATION_CREDENTIALS environment variable not set")
        }
        return try loadFromFile(path,
                                httpClient: httpClient,
                                tokenStorage: tokenStorage,
                                scopes: scopes)
    }
}

// MARK: - Base64URL Encoding Extension

extension Data {
    func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
