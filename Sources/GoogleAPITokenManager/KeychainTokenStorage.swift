import Foundation

#if os(iOS) || os(tvOS) || os(watchOS) || os(macOS)

/// Secure token storage using Keychain
public actor KeychainTokenStorage: TokenStorage {
    private let service: String
    private let accessTokenKey: String
    private let refreshTokenKey: String
    private let expirationKey: String

    public init(service: String = "GoogleAPITokenManager") {
        self.service = service
        self.accessTokenKey = "\(service).accessToken"
        self.refreshTokenKey = "\(service).refreshToken"
        self.expirationKey = "\(service).expiration"
    }

    public func storeTokens(accessToken: String, refreshToken: String?, expiresIn: TimeInterval?) throws {
        try storeString(accessToken, forKey: accessTokenKey)

        if let refreshToken = refreshToken {
            try storeString(refreshToken, forKey: refreshTokenKey)
        }

        if let expiresIn = expiresIn {
            let expirationDate = Date().addingTimeInterval(expiresIn)
            try storeString(String(expirationDate.timeIntervalSince1970), forKey: expirationKey)
        }
    }

    public func getAccessToken() throws -> String? {
        try getString(forKey: accessTokenKey)
    }

    public func getRefreshToken() throws -> String? {
        try getString(forKey: refreshTokenKey)
    }

    public func isTokenExpired() throws -> Bool {
        guard let expirationString = try getString(forKey: expirationKey),
              let expirationTimestamp = Double(expirationString) else {
            return true // If no expiration info, consider expired
        }

        let expirationDate = Date(timeIntervalSince1970: expirationTimestamp)
        return Date() >= expirationDate.addingTimeInterval(-300) // 5 minute buffer
    }

    public func clearTokens() throws {
        try deleteItem(forKey: accessTokenKey)
        try deleteItem(forKey: refreshTokenKey)
        try deleteItem(forKey: expirationKey)
    }

    private func storeString(_ value: String, forKey key: String) throws {
        let data = value.data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        // Delete existing item first
        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw Error.authenticationFailed("Failed to store token in keychain: \(status)")
        }
    }

    private func getString(forKey key: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            }
            throw Error.authenticationFailed("Failed to retrieve token from keychain: \(status)")
        }

        guard let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            throw Error.authenticationFailed("Failed to decode token from keychain")
        }

        return string
    }

    private func deleteItem(forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]

        let status = SecItemDelete(query as CFDictionary)
        // Don't throw error if item doesn't exist
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Error.authenticationFailed("Failed to delete token from keychain: \(status)")
        }
    }
}

#endif
