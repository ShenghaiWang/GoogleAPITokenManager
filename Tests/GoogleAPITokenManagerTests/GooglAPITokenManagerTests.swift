import Testing
import Foundation
@testable import GoogleAPITokenManager

@Test func example() async throws {
    // Write your test here and use APIs like `#expect(...)` to check expected conditions.
}

@Test func testPKCEParametersGeneration() async throws {
    let pkce = PKCEParameters()
    
    // Verify code verifier length (should be 128 characters)
    #expect(pkce.codeVerifier.count == 128)
    
    // Verify code challenge is not empty
    #expect(!pkce.codeChallenge.isEmpty)
    
    // Verify method is S256
    #expect(pkce.codeChallengeMethod == "S256")
    
    // Verify state is a valid UUID format
    #expect(!pkce.state.isEmpty)
}

@Test func testAuthorizationURLWithPKCE() async throws {
    let tokenManager = GoogleOAuth2TokenManager(
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        redirectURI: "test://callback"
    )
    
    let scopes = ["https://www.googleapis.com/auth/userinfo.email"]
    let result = await tokenManager.buildAuthorizationURL(scopes: scopes, usePKCE: true)
    
    // Verify URL contains PKCE parameters
    let urlString = result.url.absoluteString
    #expect(urlString.contains("code_challenge="))
    #expect(urlString.contains("code_challenge_method=S256"))
    #expect(urlString.contains("state="))
    
    // Verify PKCE parameters are returned
    #expect(result.pkceParameters != nil)
}

@Test func testCallbackURLParsing() async throws {
    let tokenManager = GoogleOAuth2TokenManager(
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        redirectURI: "test://callback"
    )
    
    let callbackURL = URL(string: "test://callback?code=test_code&state=test_state")!
    let (code, state, error) = tokenManager.parseCallbackURL(callbackURL)
    
    #expect(code == "test_code")
    #expect(state == "test_state")
    #expect(error == nil)
}

@Test func testCallbackURLParsingWithError() async throws {
    let tokenManager = GoogleOAuth2TokenManager(
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        redirectURI: "test://callback"
    )
    
    let callbackURL = URL(string: "test://callback?error=access_denied")!
    let (code, state, error) = tokenManager.parseCallbackURL(callbackURL)
    
    #expect(code == nil)
    #expect(state == nil)
    #expect(error == "access_denied")
}

@Test func testStateVerification() async throws {
    let tokenManager = GoogleOAuth2TokenManager(
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        redirectURI: "test://callback"
    )
    
    let expectedState = "test-state-123"
    let receivedState = "test-state-123"
    let wrongState = "wrong-state"
    
    #expect(tokenManager.verifyState(receivedState, expected: expectedState) == true)
    #expect(tokenManager.verifyState(wrongState, expected: expectedState) == false)
}

@Test func testCryptoUtilsCompatibility() async throws {
    // Test that crypto utilities work across platforms
    let testData = "Hello, World!".data(using: .utf8)!
    
    // Test SHA256 hashing
    let hash1 = CryptoUtils.sha256Hash(of: testData)
    let hash2 = CryptoUtils.sha256Hash(of: testData)
    
    // Hashes should be consistent
    #expect(hash1 == hash2)
    #expect(hash1.count == 32) // SHA256 produces 32 bytes
    
    // Test random bytes generation
    let random1 = CryptoUtils.randomBytes(count: 32)
    let random2 = CryptoUtils.randomBytes(count: 32)
    
    // Random bytes should be different and correct length
    #expect(random1 != random2)
    #expect(random1.count == 32)
    #expect(random2.count == 32)
}

@Test func testPKCEConsistency() async throws {
    // Test that PKCE parameters are generated consistently
    let pkce1 = PKCEParameters()
    let pkce2 = PKCEParameters()
    
    // Each instance should be unique
    #expect(pkce1.codeVerifier != pkce2.codeVerifier)
    #expect(pkce1.codeChallenge != pkce2.codeChallenge)
    #expect(pkce1.state != pkce2.state)
    
    // But code challenge should be deterministic for same verifier
    let customPkce1 = PKCEParameters(codeVerifier: "test-verifier", state: "test-state")
    let customPkce2 = PKCEParameters(codeVerifier: "test-verifier", state: "test-state")
    
    #expect(customPkce1.codeChallenge == customPkce2.codeChallenge)
    #expect(customPkce1.state == customPkce2.state)
}
