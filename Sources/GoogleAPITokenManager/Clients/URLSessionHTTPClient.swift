import Foundation

/// URLSession-based HTTP client implementation
public actor URLSessionHTTPClient: HTTPClient {
    private let session: URLSessionProtocol
    private let logger: HTTPLogger?

    public init(
        session: URLSessionProtocol = URLSession.shared,
        logger: HTTPLogger? = nil,
    ) {
        self.session = session
        self.logger = logger
    }

    public func execute<T: Codable & Sendable>(_ request: HTTPRequest) async throws -> T {
        let data = try await self.executeRawInternal(request)
        do {
            let decoder = JSONDecoder()
            return try decoder.decode(T.self, from: data)
        } catch {
            throw Error.decodingError(error)
        }
    }

    public func executeRaw(_ request: HTTPRequest) async throws -> Data {
        try await self.executeRawInternal(request)
    }

    /// Internal method that performs the actual HTTP request without retry logic
    private func executeRawInternal(_ request: HTTPRequest) async throws -> Data {        // Apply rate limiting if configured

        await logger?.logRequest(request)

        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method.rawValue
        urlRequest.httpBody = request.body

        // Set headers
        for (key, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }

        // Set default headers if not provided
        if urlRequest.value(forHTTPHeaderField: "Content-Type") == nil && request.body != nil {
            urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        do {
            let session = self.session
            let (data, response) = try await session.data(for: urlRequest)
            guard let httpResponse = response as? HTTPURLResponse else {
                let error = Error.invalidResponse("Response is not HTTPURLResponse")
                await logger?.logError(error, for: request)
                throw error
            }

            await logger?.logResponse(httpResponse, data: data)

            // Handle HTTP status codes
            switch httpResponse.statusCode {
            case 200...299:
                return data
            case 400:
                throw Error.badRequest("Bad Request")
            case 401:
                throw Error.authenticationFailed("Unauthorized")
            case 403:
                throw Error.accessDenied("Forbidden")
            case 404:
                throw Error.notFound("Not Found")
            case 429:
                let retryAfter = httpResponse.value(forHTTPHeaderField: "Retry-After")
                let retryInterval = retryAfter.flatMap(Double.init) ?? 60.0
                throw Error.rateLimitExceeded(retryAfter: retryInterval)
            case 500...599:
                throw Error.apiError(code: httpResponse.statusCode, message: "Server Error", details: nil)
            default:
                throw Error.apiError(code: httpResponse.statusCode, message: "Unknown Error", details: nil)
            }
        } catch let error as Error {
            await logger?.logError(error, for: request)
            throw error
        } catch {
            let networkError = Error.networkError(error)
            await logger?.logError(networkError, for: request)
            throw networkError
        }
    }
}
