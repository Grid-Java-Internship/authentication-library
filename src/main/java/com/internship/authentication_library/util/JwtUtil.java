package com.internship.authentication_library.util;

import com.internship.authentication_library.feign.UserDTO;
import com.internship.authentication_library.feign.AuthService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final AuthService authService;

    public boolean validateToken(String token) throws JOSEException, ParseException {
        SignedJWT signedJWT = SignedJWT.parse(token);

        if (signedJWT.getJWTClaimsSet().getClaim("rti") == null) {
            return false;
        }

        JWK jwk = JWK.parse(authService.getPublicKey(signedJWT.getHeader().getKeyID()));
        RSAKey rsaPublicKeyJwk = jwk.toRSAKey();

        RSAPublicKey publicKey = rsaPublicKeyJwk.toRSAPublicKey();

        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        return signedJWT.verify(verifier) && !isTokenExpired(token);
    }


    public String extractEmail(String token) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(token);

        return signedJWT.getJWTClaimsSet().getSubject();
    }

    private Long extractUserId(String token) throws ParseException {

        SignedJWT signedJWT = SignedJWT.parse(token);

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        return claimsSet.getLongClaim("userId");
    }

    private String extractRole(String token) throws ParseException {

        SignedJWT signedJWT = SignedJWT.parse(token);

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        return claimsSet.getStringClaim("role");
    }

    public UserDTO extractUserDTO(String token) throws ParseException {
        return UserDTO
                .builder()
                .username(String.valueOf(extractUserId(token)))
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_"+extractRole(token))))
                .build();
    }

    public boolean isTokenExpired(String token) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(token);

        return new Date().after(signedJWT.getJWTClaimsSet().getExpirationTime());
    }
}
