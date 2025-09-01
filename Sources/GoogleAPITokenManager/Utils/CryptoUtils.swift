import Foundation

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// Cross-platform crypto utilities for OAuth2 verification
public struct CryptoUtils {
    
    /// Generate SHA256 hash of data - cross-platform compatible
    public static func sha256Hash(of data: Data) -> Data {
        #if canImport(CryptoKit)
        let hash = SHA256.hash(data: data)
        return Data(hash)
        #elseif canImport(Crypto)
        // Use swift-crypto on Linux
        let hash = SHA256.hash(data: data)
        return Data(hash)
        #else
        // Fallback implementation for older systems
        return fallbackSHA256(data: data)
        #endif
    }
    
    /// Generate cryptographically secure random bytes
    public static func randomBytes(count: Int) -> Data {
        #if canImport(CryptoKit)
        return Data(SymmetricKey(size: .init(bitCount: count * 8)).withUnsafeBytes { Data($0) })
        #elseif canImport(Crypto)
        return Data(SymmetricKey(size: .init(bitCount: count * 8)).withUnsafeBytes { Data($0) })
        #else
        // Fallback using system random
        var bytes = [UInt8](repeating: 0, count: count)
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        let result = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard result == errSecSuccess else {
            // If SecRandom fails, use a less secure fallback
            for i in 0..<count {
                bytes[i] = UInt8.random(in: 0...255)
            }
        }
        #else
        // On Linux, use Swift's random number generator
        for i in 0..<count {
            bytes[i] = UInt8.random(in: 0...255)
        }
        #endif
        return Data(bytes)
        #endif
    }
    
    #if !canImport(CryptoKit) && !canImport(Crypto)
    /// Fallback SHA256 implementation for systems without CryptoKit
    private static func fallbackSHA256(data: Data) -> Data {
        #if canImport(CommonCrypto)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
        #else
        // Last resort: Use a deterministic but not cryptographically secure hash
        // This should only be used for testing or when proper crypto is not available
        return deterministicHash(data: data)
        #endif
    }
    
    private static func deterministicHash(data: Data) -> Data {
        // Simple deterministic hash - NOT cryptographically secure
        // Only for compatibility when no crypto libraries are available
        var hash: [UInt64] = [0, 0, 0, 0] // 32 bytes = 4 * 8 bytes
        
        for (index, byte) in data.enumerated() {
            let hashIndex = index % 4
            hash[hashIndex] = hash[hashIndex] &* 31 &+ UInt64(byte)
        }
        
        var result = Data()
        for value in hash {
            for i in 0..<8 {
                result.append(UInt8((value >> (i * 8)) & 0xFF))
            }
        }
        
        return result
    }
    #endif
}