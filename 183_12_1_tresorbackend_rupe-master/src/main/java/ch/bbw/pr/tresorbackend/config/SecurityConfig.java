package ch.bbw.pr.tresorbackend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
        // Should allow URLs like oAuth2/**
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/", "/api/users/login", "/api/users/register", "/oauth2/**", "/login/**").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
            .requestMatchers("/api/secrets/**").hasAnyRole("USER", "ADMIN")
            .requestMatchers(HttpMethod.GET, "/api/users/**").hasRole("ADMIN")
            .anyRequest().hasAnyRole("USER", "ADMIN")
        )
        .oauth2Login(oauth -> oauth
            .userInfoEndpoint(info -> info.userService(oAuth2UserService))
            .successHandler(oAuth2SuccessHandler)
        )
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
