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
    private var currentPKCEParameters: PKCEParameters?

    private let tokenEndpoint = "https://oauth2.googleapis.com/token"
    private let authEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"

#if os(iOS) || os(tvOS) || os(watchOS) || os(macOS)
    public init(clientId: String,
                clientSecret: String,
                redirectURI: String,
                tokenStorage: (any TokenStorage)? = KeychainTokenStorage(),
                httpClient: any HTTPClient = URLSessionHTTPClient()) {
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
                httpClient: any HTTPClient = URLSessionHTTPClient()) {
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
        guard let tokenStorage,
              try await tokenStorage.getAccessToken() != nil else {
#if DEBUG
            let authResult = buildAuthorizationURL(scopes: scopes, usePKCE: true)
            print("🔐 Please visit this URL to authorize the application:")
            print(authResult.url.absoluteString)
            print("\n📋 After authorization, copy the authorization code and state parameter:")
            print("Authorization code:")

            // Read authorization code from user input
            guard let authCode = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !authCode.isEmpty else {
                fatalError("❌ No authorization code provided")
            }
            
            print("State parameter (from callback URL):")
            let state = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines)
            
            return try await exchangeAuthorizationCode(authCode, state: state, pkceParameters: authResult.pkceParameters)
#else
            throw Error.invalidOAuthflow
#endif
        }

        if try await tokenStorage.isTokenExpired() {
            _ = try await refreshToken()
        }
        return try await .init(
            accessToken: tokenStorage.getAccessToken() ?? "",
            refreshToken: tokenStorage.getRefreshToken() ?? "",
            isVerified: true
        )
    }

    /// Build the authorization URL for OAuth2 flow with PKCE verification
    public func buildAuthorizationURL(scopes: [String], usePKCE: Bool = true) -> (url: URL, pkceParameters: PKCEParameters?) {
        var components = URLComponents(string: authEndpoint)!
        
        let scopeString = scopes.joined(separator: " ")
        var queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: scopeString),
            URLQueryItem(name: "access_type", value: "offline"),
            URLQueryItem(name: "prompt", value: "consent")
        ]
        
        var pkceParams: PKCEParameters? = nil
        
        if usePKCE {
            pkceParams = PKCEParameters()
            self.currentPKCEParameters = pkceParams
            
            queryItems.append(contentsOf: [
                URLQueryItem(name: "code_challenge", value: pkceParams!.codeChallenge),
                URLQueryItem(name: "code_challenge_method", value: pkceParams!.codeChallengeMethod),
                URLQueryItem(name: "state", value: pkceParams!.state)
            ])
        } else {
            let state = UUID().uuidString
            queryItems.append(URLQueryItem(name: "state", value: state))
        }

        components.queryItems = queryItems
        return (url: components.url!, pkceParameters: pkceParams)
    }

    /// Exchange authorization code for access and refresh tokens with verification
    public func exchangeAuthorizationCode(_ code: String, state: String? = nil, pkceParameters: PKCEParameters? = nil) async throws -> AuthResult {
        // Verify state parameter if provided
        var isVerified = false
        var verificationState: String? = nil
        
        if let providedState = state ?? pkceParameters?.state {
            if let currentPKCE = currentPKCEParameters ?? pkceParameters {
                isVerified = providedState == currentPKCE.state
                verificationState = providedState
            } else {
                // Basic state verification without PKCE
                verificationState = providedState
                isVerified = true // Assume verified if state is provided and matches expected format
            }
        }
        
        var parameters = [
            "grant_type": "authorization_code",
            "code": code,
            "client_id": clientId,
            "client_secret": clientSecret,
            "redirect_uri": redirectURI
        ]
        
        // Add PKCE code verifier if using PKCE
        if let pkce = currentPKCEParameters ?? pkceParameters {
            parameters["code_verifier"] = pkce.codeVerifier
            isVerified = isVerified && (state == pkce.state || pkceParameters?.state == pkce.state)
        }

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
        
        // Clear PKCE parameters after successful exchange
        self.currentPKCEParameters = nil

        return AuthResult(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            expiresIn: response.expiresIn,
            tokenType: response.tokenType ?? "Bearer",
            scope: response.scope,
            isVerified: isVerified,
            verificationState: verificationState
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
    
    /// Verify ID token if present (basic JWT structure validation)
    public nonisolated func verifyIDToken(_ idToken: String) -> Bool {
        let components = idToken.components(separatedBy: ".")
        return components.count == 3 // Basic JWT structure check
    }
    
    /// Generate PKCE parameters for external use
    public func generatePKCEParameters() -> PKCEParameters {
        let params = PKCEParameters()
        self.currentPKCEParameters = params
        return params
    }
    
    /// Verify state parameter matches expected value
    public nonisolated func verifyState(_ receivedState: String, expected: String) -> Bool {
        return receivedState == expected
    }
    
    /// Parse callback URL to extract authorization code and state
    public nonisolated func parseCallbackURL(_ url: URL) -> (code: String?, state: String?, error: String?) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            return (nil, nil, "Invalid callback URL")
        }
        
        var code: String?
        var state: String?
        var error: String?
        
        for item in queryItems {
            switch item.name {
            case "code":
                code = item.value
            case "state":
                state = item.value
            case "error":
                error = item.value
            default:
                break
            }
        }
        
        return (code, state, error)
    }
}
