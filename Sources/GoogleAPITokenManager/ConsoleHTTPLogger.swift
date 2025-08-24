import Foundation

/// Default implementation that logs to console
public actor ConsoleHTTPLogger: HTTPLogger {
    public init() {}

    public func logRequest(_ request: HTTPRequest) {
        print("🌐 HTTP Request: \(request.method.rawValue) \(request.url)")
        if !request.headers.isEmpty {
            print("📋 Headers: \(request.headers)")
        }
        if let body = request.body, let bodyString = String(data: body, encoding: .utf8) {
            print("📦 Body: \(bodyString)")
        }
    }

    public func logResponse(_ response: HTTPURLResponse, data: Data) {
        print("✅ HTTP Response: \(response.statusCode) from \(response.url?.absoluteString ?? "unknown")")
        if let responseString = String(data: data, encoding: .utf8) {
            print("📥 Response Data: \(responseString)")
        }
    }

    public func logError(_ error: Swift.Error, for request: HTTPRequest) {
        print("❌ HTTP Error for \(request.method.rawValue) \(request.url): \(error)")
    }
}
