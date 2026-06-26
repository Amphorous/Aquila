package org.hoyo.aquila.security.component;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

// Signs the Aquila-User-Key/Aquila-Request-Timestamp headers forwarded to downstream
// services so they can verify the request actually came through the gateway.
@Component
public class GatewayRequestSigner {

    private final SecretKeySpec secretKeySpec;

    public GatewayRequestSigner(@Value("${application.security.gateway-signing-secret}") String secret) {
        this.secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    public String sign(String userKey, String timestamp) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            byte[] result = mac.doFinal((userKey + ":" + timestamp).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("Failed signing gateway request", e);
        }
    }
}
