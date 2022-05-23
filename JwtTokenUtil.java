package com.cards.auth.security;

import com.cards.auth.exceptions.BizException;
import com.google.common.base.Splitter;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
public class JwtTokenUtil {

    private final String secretKey;
    private final SecretKeySpec secretKeySpec;
    private static final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS512;

    @Autowired
    public JwtTokenUtil(@Value("${spring.security.user.password}") final String secretKey, final SecretKeySpec secretKeySpec){
        this.secretKey = secretKey;
        this.secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), signatureAlgorithm.getJcaName());
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKeySpec).parseClaimsJws(token).getBody().getSubject();
    }

    public static void validateJwtToken(String authorizationHeader) {

        final List<String> tokens = Splitter.on(" ").trimResults().omitEmptyStrings().splitToList(authorizationHeader);
        if (tokens.size() != 2) {
            log.error("Authorization token must be in form of 'Bearer xxx...'");
            throw new BizException("Invalid authorization token");
        }
        if (!tokens.get(0).equals("Bearer")) {
            log.error("Authorization token doesn't starts with Bearer");
            throw new BizException("Invalid JWT authorization token");
        }
    }
}

