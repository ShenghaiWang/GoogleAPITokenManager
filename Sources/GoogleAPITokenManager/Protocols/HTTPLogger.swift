import Foundation

/// Logger protocol for HTTP operations
public protocol HTTPLogger: Actor {
    func logRequest(_ request: HTTPRequest) async
    func logResponse(_ response: HTTPURLResponse, data: Data) async
    func logError(_ error: Swift.Error, for request: HTTPRequest) async
}
