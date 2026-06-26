package org.hoyo.aquila.security.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

// Derives a stable, one-way pseudonymous identifier from a platform user ID
// (e.g. a Discord user ID). Deterministic so the same input always maps to the
// same Redis-key component across logins, but not reversible.
@Component
public class UserKeyHasher {

    private final SecretKeySpec secretKeySpec;

    public UserKeyHasher(@Value("${application.security.user-key-secret}") String secret) {
        this.secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    public String hash(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            byte[] result = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("Failed hashing user key", e);
        }
    }
}
