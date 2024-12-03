package comp3911.cwk2;

import java.security.SecureRandom;
import java.util.Base64;

public class CSRFTokenGenerator {

    public static String generateToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] token = new byte[32]; // 256-bit token
        secureRandom.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
}
