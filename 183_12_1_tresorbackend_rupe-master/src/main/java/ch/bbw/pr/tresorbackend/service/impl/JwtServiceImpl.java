package ch.bbw.pr.tresorbackend.service.impl;

import ch.bbw.pr.tresorbackend.util.JwtUtil;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtServiceImpl {
    private final JwtUtil jwtUtil;

    public JwtServiceImpl(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    public String extractUsername(String token) {
        return jwtUtil.extractSubject(token);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username != null &&
               username.equals(userDetails.getUsername()) &&
               jwtUtil.validateToken(token);
    }
}