import Foundation

/// Protocol for URLSession abstraction to enable testing
public protocol URLSessionProtocol: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

/// Extension to make URLSession conform to URLSessionProtocol
extension URLSession: URLSessionProtocol {}
