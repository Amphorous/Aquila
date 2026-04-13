package org.hoyo.aquila.security;

import org.hoyo.aquila.security.configuration.AESUtil;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
// Notice: @CrossOrigin is gone! Your SecurityConfig handles this dynamically now.
public class AuthStatusController {

    @GetMapping("/api/auth/status")
    public Mono<Map<String, Object>> authStatus(Mono<Authentication> authenticationMono) {

        // We use map() to process the authentication object only if it exists
        return authenticationMono.map(authentication -> {
            Map<String, Object> response = new HashMap<>();

            boolean isRealUser = authentication.isAuthenticated()
                    && !(authentication instanceof AnonymousAuthenticationToken);

            if (isRealUser && authentication instanceof OAuth2AuthenticationToken) {
                OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
                OAuth2User principal = oauthToken.getPrincipal(); // Extract principal here
                String platform = oauthToken.getAuthorizedClientRegistrationId(); // e.g., "discord"

                String avatarUrl = null;

                if ("discord".equals(platform)) {
                    String userId = principal.getAttribute("id");
                    String avatarHash = principal.getAttribute("avatar");

                    if (userId != null && avatarHash != null) {
                        // Custom avatar
                        avatarUrl = String.format(
                                "https://cdn.discordapp.com/avatars/%s/%s.png",
                                userId, avatarHash
                        );
                    } else if (userId != null) {
                        // Default avatar
                        String discriminator = principal.getAttribute("discriminator");
                        int discIndex = 0;
                        try {
                            discIndex = Integer.parseInt(discriminator) % 5;
                        } catch (Exception ignored) {}
                        avatarUrl = String.format(
                                "https://cdn.discordapp.com/embed/avatars/%d.png",
                                discIndex
                        );
                    }

                    String key = principal.getAttribute("username");
                    try {
                        String encrypted_key = AESUtil.encrypt(key);
                        response.put("ENCRYPTED_KEY", encrypted_key);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }

                response.put("authenticated", true);
                response.put("username", principal.getAttribute("global_name"));
                response.put("platform", platform);
                response.put("avatarUrl", avatarUrl);

            } else {
                response.put("authenticated", false);
            }

            return response;

        }).defaultIfEmpty(Map.of("authenticated", false)); // Fallback if no auth context exists
    }

    @GetMapping("/csrf-token")
    public Mono<CsrfToken> csrf(ServerWebExchange exchange) {
        // In WebFlux, the CsrfToken is extracted directly from the exchange attributes
        Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken : Mono.empty();
    }
}