package ch.bbw.pr.tresorbackend.service.impl;

import java.security.SecureRandom;
import org.apache.commons.codec.binary.Base32;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public class TOTPSecretGenerator {
    public static String generateSecret() {
        byte[] buffer = new byte[20]; // 160-bit secret (recommended)
        new SecureRandom().nextBytes(buffer);
        Base32 base32 = new Base32();
        return base32.encodeToString(buffer).replace("=", "");
    }

    public static boolean verifyToken(String secret, int code) {
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        return gAuth.authorize(secret, code);
    }

    public static void main(String[] args) {
        String secret = generateSecret();
        System.out.println("TOTP Secret: " + secret);
    }
}
