package ch.bbw.pr.tresorbackend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import jakarta.servlet.http.HttpServletResponse;

import ch.bbw.pr.tresorbackend.repository.UserRepository;
import ch.bbw.pr.tresorbackend.service.impl.CustomOAuth2SuccessHandlerImpl;
import ch.bbw.pr.tresorbackend.service.impl.CustomOAuth2UserServiceImpl;
import ch.bbw.pr.tresorbackend.service.impl.JwtAuthFilterImpl;
import ch.bbw.pr.tresorbackend.service.impl.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthFilterImpl jwtAuthFilter,
            CustomOAuth2UserServiceImpl oAuth2UserService,
            CustomOAuth2SuccessHandlerImpl oAuth2SuccessHandler) throws Exception {
        http
                // Not good for production, but oke for development
                // Should allow URLs like o.e. oAuth2/**
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/api/users/login", "/api/users/register", "/oauth2/**",
                                "/login/oauth2/code/**", "/api/users/request-password-reset",
                                "/api/users/reset-password")
                        .permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                        .requestMatchers("/api/secrets/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/users/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((request, response, authException) -> {
                            if (request.getRequestURI().contains("/oauth2/authorization")) {
                                response.setStatus(HttpServletResponse.SC_OK);
                                response.setContentType("application/json");
                                String redirectUrl = "/oauth2/authorization/google"; // Adjust if needed for other
                                                                                     // providers
                                new ObjectMapper().writeValue(response.getWriter(), Map.of("redirectUrl", redirectUrl));
                            } else {
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED).commence(request, response,
                                        authException);
                            }
                        }))
                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(info -> info.userService(oAuth2UserService))
                        .successHandler(oAuth2SuccessHandler))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public UserDetailsService users(UserRepository userRepository) {
        return new UserDetailsServiceImpl(userRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
