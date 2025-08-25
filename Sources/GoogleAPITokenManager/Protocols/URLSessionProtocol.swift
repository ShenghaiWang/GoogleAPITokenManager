import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Protocol for URLSession abstraction to enable testing
public protocol URLSessionProtocol: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

/// Extension to make URLSession conform to URLSessionProtocol
#if canImport(FoundationNetworking)
extension URLSession: URLSessionProtocol {
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        // Linux implementation using completion handler
        return try await withCheckedThrowingContinuation { continuation in
            let task = self.dataTask(with: request) { data, response, error in
                // Handle error cases
                if let error = error {
                    continuation.resume(throwing: error)
                    return
                }

                // Ensure we have both data and response
                guard let response = response else {
                    let error = URLError(.badServerResponse, userInfo: [
                        NSLocalizedDescriptionKey: "No response received from server"
                    ])
                    continuation.resume(throwing: error)
                    return
                }

                // Data can be empty but should exist
                let responseData = data ?? Data()
                continuation.resume(returning: (responseData, response))
            }

            // Start the task
            task.resume()
        }
    }
}
#else
extension URLSession: URLSessionProtocol {}
#endif
