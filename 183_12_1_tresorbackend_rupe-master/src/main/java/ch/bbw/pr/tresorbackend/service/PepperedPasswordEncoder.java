package ch.bbw.pr.tresorbackend.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * A PasswordEncoder decorator that adds a configured pepper before encoding or
 * matching.
 */
@Component // Make it a Spring component
@RequiredArgsConstructor
public class PepperedPasswordEncoder implements PasswordEncoder {

    // Inject the primary PasswordEncoder bean (BCryptPasswordEncoder)
    private final PasswordEncoder delegate;

    @Value("${com.example.pepper.value}")
    private String pepper;

    @Override
    public String encode(CharSequence rawPassword) {
        return delegate.encode(rawPassword + pepper);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return delegate.matches(rawPassword + pepper, encodedPassword);
    }

    // Optional: Implement upgradeEncoding if needed, delegating and peppering
    // @Override
    // public boolean upgradeEncoding(String encodedPassword) {
    // return delegate.upgradeEncoding(encodedPassword);
    // }
}
