package ch.bbw.pr.tresorbackend.service.impl;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import ch.bbw.pr.tresorbackend.repository.UserRepository;
import ch.bbw.pr.tresorbackend.util.JwtUtil;
import ch.bbw.pr.tresorbackend.model.User;
import org.springframework.web.util.UriComponentsBuilder;
import java.io.IOException;

@Component
public class CustomOAuth2SuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public CustomOAuth2SuccessHandlerImpl(UserRepository userRepository, JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {
        
        var principal = (DefaultOAuth2User) authentication.getPrincipal();
        String email = principal.getAttribute("email");
        String name = principal.getAttribute("name");
        String googleId = principal.getAttribute("sub"); // Google's unique user ID
        
        // Find existing user or create new one
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> createNewUser(email, name, googleId));
        
        String jwt = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
        
        String redirectUrl = UriComponentsBuilder
                .fromUriString("http://localhost:3000/oauth2/redirect")
                .queryParam("token", jwt)
                .queryParam("email", user.getEmail())
                .queryParam("userId", user.getId())
                .queryParam("password", user.getPassword()) // Not optimal, but ok for test app
                .build().toUriString();
        
        response.sendRedirect(redirectUrl);
    }
    
    private User createNewUser(String email, String name, String googleId) {
        User newUser = new User();
        newUser.setEmail(email);
        newUser.setFirstName(name); // Not optimal, but ok for test app
        newUser.setLastName(name);
        newUser.setPassword(googleId); // Use Google ID as password placeholder (workaround'ish)
        newUser.setRole(User.Role.USER); // default role
        
        return userRepository.save(newUser);
    }
}