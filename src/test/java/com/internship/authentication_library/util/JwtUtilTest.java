package com.internship.authentication_library.util;

import com.internship.authentication_library.feign.AuthService;
import com.internship.authentication_library.feign.UserDTO;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import feign.FeignException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    @Mock
    private AuthService authService;

    @InjectMocks
    private JwtUtil jwtUtil;

    private RSAKey testRsaKey;
    private RSAKey anotherRsaKey;
    private String testKid;

    @BeforeEach
    void setUp() throws JOSEException {
        testKid = UUID.randomUUID().toString();
        testRsaKey = new RSAKeyGenerator(2048)
                .keyID(testKid)
                .generate();
        anotherRsaKey = new RSAKeyGenerator(2048)
                .keyID("different-kid")
                .generate();
    }

    private String generateTestToken(String subject, long userId, String role, String kid, RSAKey signingKey, long expirationMillis, boolean includeRti) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("test-issuer")
                .expirationTime(new Date(System.currentTimeMillis() + expirationMillis))
                .issueTime(new Date())
                .jwtID(UUID.randomUUID().toString())
                .claim("userId", userId)
                .claim("role", role);

        if (includeRti) {
            claimsBuilder.claim("rti", UUID.randomUUID().toString());
        }

        JWTClaimsSet claimsSet = claimsBuilder.build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(kid)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner signer = new RSASSASigner(signingKey);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    @Test
    void validateToken_shouldReturnTrue_whenTokenIsValid() throws Exception {
        String validToken = generateTestToken("test@example.com", 1L, "USER",
                testKid, testRsaKey, 60000, true);
        String publicKeyJwkString = testRsaKey.toPublicJWK().toJSONString();

        when(authService.getPublicKey(testKid)).thenReturn(publicKeyJwkString);

        boolean isValid = jwtUtil.validateToken(validToken);

        assertTrue(isValid);
        verify(authService, times(1)).getPublicKey(testKid);
    }

    @Test
    void validateToken_shouldThrowParseException_whenTokenIsMalformed() {
        String malformedToken = "this.is.not.a.jwt";

        assertThrows(ParseException.class, () -> {
            jwtUtil.validateToken(malformedToken);
        });
        verifyNoInteractions(authService);
    }

    @Test
    void validateToken_shouldReturnFalse_whenRtiClaimIsMissing() throws Exception {
        String tokenWithoutRti = generateTestToken("test@example.com", 1L, "USER",
                testKid, testRsaKey, 60000, false);

        boolean isValid = jwtUtil.validateToken(tokenWithoutRti);

        assertFalse(isValid);
        verifyNoInteractions(authService);
    }


    @Test
    void validateToken_shouldReturnFalse_whenSignatureIsInvalid() throws Exception {
        String tokenSignedWithAnotherKey = generateTestToken("test@example.com", 1L, "USER",
                testKid, anotherRsaKey, 60000, true);
        String correctPublicKeyJwkString = testRsaKey.toPublicJWK().toJSONString();

        when(authService.getPublicKey(testKid)).thenReturn(correctPublicKeyJwkString);

        boolean isValid = jwtUtil.validateToken(tokenSignedWithAnotherKey);

        assertFalse(isValid);
        verify(authService, times(1)).getPublicKey(testKid);
    }

    @Test
    void validateToken_shouldReturnFalse_whenTokenIsExpired() throws Exception {
        String expiredToken = generateTestToken("test@example.com", 1L, "USER",
                testKid, testRsaKey, -10000, true);
        String publicKeyJwkString = testRsaKey.toPublicJWK().toJSONString();

        when(authService.getPublicKey(testKid)).thenReturn(publicKeyJwkString);

        boolean isValid = jwtUtil.validateToken(expiredToken);

        assertFalse(isValid);
        verify(authService, times(1)).getPublicKey(testKid);
    }

    @Test
    void validateToken_shouldThrowException_whenAuthServiceFails() throws Exception {
        String validToken = generateTestToken("test@example.com", 1L, "USER",
                testKid, testRsaKey, 60000, true);

        when(authService.getPublicKey(testKid)).thenThrow(FeignException.InternalServerError.class);

        assertThrows(FeignException.class, () -> {
            jwtUtil.validateToken(validToken);
        });
        verify(authService, times(1)).getPublicKey(testKid);
    }

    @Test
    void extractEmail_shouldReturnCorrectEmail() throws Exception {
        String expectedEmail = "user@domain.com";
        String token = generateTestToken(expectedEmail, 1L, "USER",
                testKid, testRsaKey, 60000, true);

        String actualEmail = jwtUtil.extractEmail(token);

        assertEquals(expectedEmail, actualEmail);
    }

    @Test
    void extractEmail_shouldThrowParseException_whenTokenIsMalformed() {
        String malformedToken = "invalid.token";

        assertThrows(ParseException.class, () -> {
            jwtUtil.extractEmail(malformedToken);
        });
    }

    @Test
    void extractUserDTO_shouldReturnCorrectUserDTO() throws Exception {
        long expectedUserId = 123L;
        String expectedRole = "ADMIN";
        String token = generateTestToken("test@test.com", expectedUserId, expectedRole, testKid,
                testRsaKey, 60000, true);

        UserDTO userDTO = jwtUtil.extractUserDTO(token);

        assertNotNull(userDTO);
        assertEquals(String.valueOf(expectedUserId), userDTO.getUsername());
        assertNotNull(userDTO.getAuthorities());

        List<SimpleGrantedAuthority> expectedAuthorities = List.of
                (new SimpleGrantedAuthority("ROLE_" + expectedRole));
        assertEquals(expectedAuthorities, userDTO.getAuthorities());
    }

    @Test
    void extractUserDTO_shouldThrowParseException_whenTokenIsMalformed() {
        String malformedToken = "bad.jwt.token";

        assertThrows(ParseException.class, () -> {
            jwtUtil.extractUserDTO(malformedToken);
        });
    }

    @Test
    void extractUserDTO_shouldHandleMissingUserIdClaim() throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("test@test.com")
                .issuer("test-issuer")
                .expirationTime(new Date(System.currentTimeMillis() + 60000))
                .claim("role", "USER")
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(testKid).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new RSASSASigner(testRsaKey));
        String token = signedJWT.serialize();

        UserDTO userDTO = jwtUtil.extractUserDTO(token);
        assertEquals("null", userDTO.getUsername());

        List<SimpleGrantedAuthority> expectedAuthorities = List.of
                (new SimpleGrantedAuthority("ROLE_USER"));
        assertEquals(expectedAuthorities, userDTO.getAuthorities());
    }

    @Test
    void isTokenExpired_shouldReturnTrue_whenTokenIsExpired() throws Exception {
        String expiredToken = generateTestToken("test@example.com", 1L, "USER",
                testKid, testRsaKey, -10000, true);
        assertTrue(jwtUtil.isTokenExpired(expiredToken));
    }

    @Test
    void isTokenExpired_shouldReturnFalse_whenTokenIsNotExpired() throws Exception {
        String validToken = generateTestToken("test@example.com", 1L, "USER",
                testKid, testRsaKey, 60000, true);
        assertFalse(jwtUtil.isTokenExpired(validToken));
    }

    @Test
    void isTokenExpired_shouldThrowParseException_whenTokenIsMalformed() {
        String malformedToken = "invalid.token";
        assertThrows(ParseException.class, () -> {
            jwtUtil.isTokenExpired(malformedToken);
        });
    }
}
