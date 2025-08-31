import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Google OAuth2 token manager implementation
public actor GoogleOAuth2TokenManager: TokenManager {
    private let clientId: String
    private let clientSecret: String
    private let redirectURI: String
    private let tokenStorage: (any TokenStorage)?
    private let httpClient: any HTTPClient

    private let tokenEndpoint = "https://oauth2.googleapis.com/token"
    private let authEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"

#if os(iOS) || os(tvOS) || os(watchOS) || os(macOS)
    public init(clientId: String,
                clientSecret: String,
                redirectURI: String,
                tokenStorage: (any TokenStorage)? = KeychainTokenStorage(),
                httpClient: any HTTPClient) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.tokenStorage = tokenStorage
        self.httpClient = httpClient
    }
#else
    public init(clientId: String,
                clientSecret: String,
                redirectURI: String,
                tokenStorage: (any TokenStorage)? = InMemoeryTokenStorage(),
                httpClient: any HTTPClient) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.tokenStorage = tokenStorage
        self.httpClient = httpClient
    }
#endif
    public func isAuthenticated() async -> Bool {
        do {
            guard let tokenStorage,
                    try await tokenStorage.getAccessToken() != nil else { return false }
            return await !(try tokenStorage.isTokenExpired())
        } catch {
            return false
        }
    }

    public func getAccessToken() async throws -> String {
        guard let  tokenStorage else {
            throw Error.tokenExpired
        }
        // Check if we have a valid access token
        if let accessToken = try await tokenStorage.getAccessToken(),
           await !(try tokenStorage.isTokenExpired()) {
            return accessToken
        }

        // Try to refresh the token if we have a refresh token
        if try await tokenStorage.getRefreshToken() != nil {
            return try await refreshToken()
        }
        throw Error.tokenExpired
    }

    public func refreshToken() async throws -> String {
        guard let refreshToken = try await tokenStorage?.getRefreshToken() else {
            throw Error.authenticationFailed("No refresh token available")
        }

        let parameters = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": clientId,
            "client_secret": clientSecret
        ]

        let body = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
            .data(using: .utf8)!

        let request = HTTPRequest(
            method: .POST,
            url: URL(string: tokenEndpoint)!,
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: body
        )

        let response: TokenResponse = try await httpClient.execute(request)

        // Store the new tokens
        try await tokenStorage?.storeTokens(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken ?? refreshToken, // Keep existing refresh token if not provided
            expiresIn: response.expiresIn
        )

        return response.accessToken
    }

    public func authenticate(scopes: [String]) async throws -> AuthResult {
        #if DEBUG
        let authURL = buildAuthorizationURL(scopes: scopes)
        print("🔐 Please visit this URL to authorize the application:")
        print(authURL.absoluteString)
        print("\n📋 After authorization, copy the authorization code and paste it here:")

        // Read authorization code from user input
        guard let authCode = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines),
              !authCode.isEmpty else {
            fatalError("❌ No authorization code provided")
        }
        return try await exchangeAuthorizationCode(authCode)
        #endif
        // In a real implementation, you would:
        // 1. Generate authorization URL using buildAuthorizationURL(scopes: scopes)
        // 2. Open the authorization URL in a web view or system browser
        // 3. Handle the redirect back to your app with the authorization code
        // 4. Exchange the authorization code for tokens using exchangeAuthorizationCode()

        // For now, we'll throw an error indicating this needs to be implemented by the client
        throw Error.authenticationFailed("Authentication flow requires manual implementation. Use buildAuthorizationURL() to get the auth URL, then call exchangeAuthorizationCode() with the received code.")
    }

    /// Build the authorization URL for OAuth2 flow
    public func buildAuthorizationURL(scopes: [String], state: String? = nil) -> URL {
        var components = URLComponents(string: authEndpoint)!

        let scopeString = scopes.joined(separator: " ")
        let stateValue = state ?? UUID().uuidString

        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: scopeString),
            URLQueryItem(name: "access_type", value: "offline"),
            URLQueryItem(name: "prompt", value: "consent"),
            URLQueryItem(name: "state", value: stateValue)
        ]

        return components.url!
    }

    /// Exchange authorization code for access and refresh tokens
    public func exchangeAuthorizationCode(_ code: String, state: String? = nil) async throws -> AuthResult {
        let parameters = [
            "grant_type": "authorization_code",
            "code": code,
            "client_id": clientId,
            "client_secret": clientSecret,
            "redirect_uri": redirectURI
        ]

        let body = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
            .data(using: .utf8)!

        let request = HTTPRequest(
            method: .POST,
            url: URL(string: tokenEndpoint)!,
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: body
        )

        let response: TokenResponse = try await httpClient.execute(request)

        // Store the tokens
        try await tokenStorage?.storeTokens(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            expiresIn: response.expiresIn
        )

        return AuthResult(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            expiresIn: response.expiresIn,
            tokenType: response.tokenType ?? "Bearer",
            scope: response.scope
        )
    }

    public func clearTokens() async throws {
        try await tokenStorage?.clearTokens()
    }

    // Helper method for testing and manual token setting
    public func setTokens(accessToken: String, refreshToken: String?, expiresIn: TimeInterval?) async throws {
        try await tokenStorage?.storeTokens(
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresIn: expiresIn
        )
    }
}
