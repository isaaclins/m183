package ch.bbw.pr.tresorbackend.service.impl;

import ch.bbw.pr.tresorbackend.service.ReCaptchaService;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import java.util.HashMap;
import java.util.Map;

@Service
public class ReCaptchaServiceImpl implements ReCaptchaService {
    private static final Logger logger = LoggerFactory.getLogger(ReCaptchaServiceImpl.class);

    @Value("${google.recaptcha.secret}")
    private String recaptchaSecret;
    private final String RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    @Override
    public boolean verifyCaptcha(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        RestTemplate restTemplate = new RestTemplate();
        String url = RECAPTCHA_VERIFY_URL + "?secret=" + recaptchaSecret + "&response=" + token;
        try {
            Map<String, Object> response = restTemplate.postForObject(url, null, Map.class);
            if (response != null && response.containsKey("success")) {
                logger.info("ReCaptcha verification response: " + response);
                return (Boolean) response.get("success");
            }
        } catch (Exception e) {
            logger.error("ReCaptcha verification failed: " + e.getMessage());
        }
        return false;
    }
}
