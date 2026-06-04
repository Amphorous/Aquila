package org.hoyo.aquila.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Slf4j
@Service
@RequiredArgsConstructor
public class BinderService {

    private final UserRegistryService userRegistryService;
    private static final String VERIFICATION_SECRET = "bayeksiwamighthave_missedyou1989";
    private final WebClient.Builder webClientBuilder;

    /**
     * Generates the code that the user must place
     * into their game profile bio/signature.
     */
    public Mono<String> generateBindingCode(String encryptedKey, String game, String uid) {
        try {
            return Mono.just(generateVerificationCode(encryptedKey, game, uid));

        } catch (Exception e) {
            return Mono.error(new RuntimeException("Failed generating binding code", e));
        }
    }

    /**
     * Checks whether the user has placed the expected
     * verification code into their game profile.
     *
     * If successful:
     * - UID is linked to account.
     * - Returns true.
     */
    public Mono<Boolean> verifyBinding(String encryptedKey, String game, String uid) {
        try {
            String expectedCode = generateVerificationCode(encryptedKey, game, uid);

            return fetchUserBio(game, uid)
                    .map(bio -> bio.contains(expectedCode))
                    .flatMap(verified -> {
                        if (!verified) {
                            return Mono.just(false);
                        }

                        return userRegistryService
                                .linkValidatedUid(encryptedKey, game, uid)
                                .thenReturn(true);
                    })
                    .defaultIfEmpty(false)
                    .doOnSuccess(result -> {
                        if (result) {
                            log.info("Successfully verified {} UID [{}]", game, uid);
                        }
                    });

        } catch (Exception e) {
            return Mono.error(new RuntimeException("Failed verifying binding", e));
        }
    }

    /**
     * Generates a deterministic six-digit code.
     *
     * @return String
     */
    private String generateVerificationCode(String encryptedKey, String game, String uid) {
        try {
            String payload = encryptedKey + ":" + game + ":" + uid;
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    VERIFICATION_SECRET.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
            );
            mac.init(secretKeySpec);

            byte[] hash = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            long value = 0;
            for (int i = 0; i < 4; i++) {
                value = (value << 8) | (hash[i] & 0xFF);
            }
            int code = 100000 + (int) (Math.abs(value) % 900000);
            return String.valueOf(code);
        } catch (Exception e) {
            throw new RuntimeException("Failed generating verification code", e);
        }
    }

    /**
     * Queries a game's public profile and returns
     * the visible bio/signature/status text.
     *
     *@return Mono<String> containing bio text.
     */
    private Mono<String> fetchUserBio(String game, String uid) {
        if (game.equals("hsr")) {
            return webClientBuilder.build()
                    .get()
                    .uri("http://delta-me13/user/bio/{uid}", uid)
                    .retrieve()
                    .bodyToMono(String.class);
        }
        return Mono.error(new RuntimeException("Invalid game code"));
    }
}