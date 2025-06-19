package ch.bbw.pr.tresorbackend.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

@Component
public class JwtUtil {
    // It's recommended to load the key from a secure location in production
    private final Key key = Keys.hmacShaKeyFor("your-256-bit-secret-key-here-must-be-long-enough".getBytes(StandardCharsets.UTF_8));    private final long expirationMs = 86400000; // 24 hours

    public String generateToken(String subject, String role) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);
        
        return Jwts.builder()
                .subject(subject)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public String extractSubject(String token) {
        return parseClaims(token).getPayload().getSubject();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private Jws<Claims> parseClaims(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key)
                .build()
                .parseSignedClaims(token);
    }

    public String extractRole(String token) {
        return parseClaims(token).getPayload().get("role", String.class);
    }
}