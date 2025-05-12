package ch.bbw.pr.tresorbackend;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // Enable Spring Security's web security support
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers(HttpMethod.POST, "/api/users").permitAll() // Allow user registration
                        .requestMatchers("/public/**", "/error").permitAll() // Allow access to public resources and
                                                                             // error pages
                        .anyRequest().authenticated() // Require authentication for any other request
                )
                .formLogin(Customizer.withDefaults()) // Enable form-based login
                .httpBasic(Customizer.withDefaults()) // Enable basic authentication (optional)
                .csrf(csrf -> csrf.disable()); // Disable CSRF for simplicity in this API context (consider enabling
                                               // later with proper token handling)
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Use BCrypt with default strength (currently 10)
        return new BCryptPasswordEncoder();
    }
}
