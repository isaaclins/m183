package ch.bbw.pr.tresorbackend.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import ch.bbw.pr.tresorbackend.model.ConfigProperties;

@Configuration
public class CorsConfig {

    private static final Logger logger = LoggerFactory.getLogger(CorsConfig.class);

    @Autowired
    private ConfigProperties configProperties;

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                logger.info("Applying CORS settings...");

                // Allowing specific origins for production and dev
                registry.addMapping("/**") // Adjust the API path as needed
                        .allowedOrigins(configProperties.getOrigin()) // Replace with your actual

                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Adjust allowed methods as needed
                        .allowedHeaders("Content-Type", "Authorization", "X-Requested-With") // Allowed headers
                        .allowCredentials(true) // Allow credentials (cookies, headers)
                        .maxAge(3600); // Cache preflight request for 1 hour

                logger.info("CORS configuration loaded successfully!");
            }
        };
    }
}
