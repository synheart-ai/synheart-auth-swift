import Foundation

/// Protocol for network calls, enabling test injection with mock responses.
protocol AuthNetworking: Sendable {
    func fetchChallenge(appId: String) async throws -> ChallengeResponse
    func registerDevice(request: RegisterRequest) async throws -> RegisterResponse
    func rotateKey(request: RotateKeyRequest) async throws -> RotateKeyResponse
}

/// URLSession-based HTTP client for the Synheart auth service.
final class AuthNetworkClient: AuthNetworking, @unchecked Sendable {
    private let baseUrl: URL
    private let session: URLSession
    private let logger = AuthLogger.shared
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init(baseUrl: URL, session: URLSession = .shared) {
        self.baseUrl = baseUrl
        self.session = session
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
    }

    // MARK: - Challenge

    func fetchChallenge(appId: String) async throws -> ChallengeResponse {
        let url = baseUrl.appendingPathComponent("v1/device/challenge")
        let body = ChallengeRequest(appId: appId)
        let data = try await postRaw(url: url, body: body)
        return try ChallengeResponse.fromApiData(data)
    }

    // MARK: - Register

    func registerDevice(request: RegisterRequest) async throws -> RegisterResponse {
        let url = baseUrl.appendingPathComponent("v1/device/register")
        let data = try await postRaw(url: url, body: request)
        return try RegisterResponse.fromApiData(data)
    }

    // MARK: - Rotate Key

    func rotateKey(request: RotateKeyRequest) async throws -> RotateKeyResponse {
        let url = baseUrl.appendingPathComponent("v1/device/rotate-key")
        let data = try await postRaw(url: url, body: request)
        return try RotateKeyResponse.fromApiData(data)
    }

    // MARK: - HTTP Helpers

    private func postRaw<Req: Encodable>(url: URL, body: Req) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(body)

        let (data, response) = try await performRequest(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw SynheartAuthError.networkError("Invalid response type")
        }

        if httpResponse.statusCode >= 200 && httpResponse.statusCode < 300 {
            return data
        }

        if let errorResponse = try? decoder.decode(AuthErrorResponse.self, from: data) {
            if errorResponse.code == "CLOCK_SKEW", errorResponse.serverTimestamp != nil {
                throw SynheartAuthError.clockSkew
            }
            throw SynheartAuthError.serverError(code: errorResponse.code, message: errorResponse.message)
        }

        throw SynheartAuthError.networkError("HTTP \(httpResponse.statusCode)")
    }

    private func post<Req: Encodable, Res: Decodable>(url: URL, body: Req) async throws -> Res {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(body)

        let (data, response) = try await performRequest(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw SynheartAuthError.networkError("Invalid response type")
        }

        if httpResponse.statusCode >= 200 && httpResponse.statusCode < 300 {
            return try decoder.decode(Res.self, from: data)
        }

        // Try to parse error response
        if let errorResponse = try? decoder.decode(AuthErrorResponse.self, from: data) {
            if errorResponse.code == "CLOCK_SKEW", errorResponse.serverTimestamp != nil {
                throw SynheartAuthError.clockSkew
            }
            throw SynheartAuthError.serverError(code: errorResponse.code, message: errorResponse.message)
        }

        throw SynheartAuthError.networkError("HTTP \(httpResponse.statusCode)")
    }

    private func performRequest(_ request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await session.data(for: request)
        } catch {
            throw SynheartAuthError.networkError(error.localizedDescription)
        }
    }
}

/// Mock network client for testing.
final class MockAuthNetworkClient: AuthNetworking, @unchecked Sendable {
    var challengeResult: Result<ChallengeResponse, Error> = .failure(SynheartAuthError.networkError("Not configured"))
    var registerResult: Result<RegisterResponse, Error> = .failure(SynheartAuthError.networkError("Not configured"))
    var rotateResult: Result<RotateKeyResponse, Error> = .failure(SynheartAuthError.networkError("Not configured"))

    var fetchChallengeCallCount = 0
    var registerCallCount = 0
    var rotateCallCount = 0

    var lastRegisterRequest: RegisterRequest?
    var lastRotateRequest: RotateKeyRequest?

    func fetchChallenge(appId: String) async throws -> ChallengeResponse {
        fetchChallengeCallCount += 1
        return try challengeResult.get()
    }

    func registerDevice(request: RegisterRequest) async throws -> RegisterResponse {
        registerCallCount += 1
        lastRegisterRequest = request
        return try registerResult.get()
    }

    func rotateKey(request: RotateKeyRequest) async throws -> RotateKeyResponse {
        rotateCallCount += 1
        lastRotateRequest = request
        return try rotateResult.get()
    }
}
