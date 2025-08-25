import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Protocol for HTTP client implementations
public protocol HTTPClient: Actor {
    /// Execute an HTTP request and decode the response
    func execute<T: Codable & Sendable>(_ request: HTTPRequest) async throws -> T

    /// Execute an HTTP request and return raw data
    func executeRaw(_ request: HTTPRequest) async throws -> Data
}
