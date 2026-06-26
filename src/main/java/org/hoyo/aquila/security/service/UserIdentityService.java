package org.hoyo.aquila.security.service;

import lombok.RequiredArgsConstructor;
import org.hoyo.aquila.security.configuration.UserKeyHasher;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserIdentityService {

    private final UserKeyHasher userKeyHasher;

    public String getEncryptedKey(OAuth2AuthenticationToken oauthToken) {

        OAuth2User principal = oauthToken.getPrincipal();
        String platform = oauthToken.getAuthorizedClientRegistrationId();
        String platformUserId;

        switch (platform) {
            case "discord":
                platformUserId = principal.getAttribute("id");
                break;
            default:
                throw new IllegalArgumentException("Unsupported platform: " + platform);
        }

        return userKeyHasher.hash(platformUserId) + ":" + platform;
    }

    public Mono<String> getEncryptedKeyMono(Mono<Authentication> authenticationMono) {
        return getOAuthToken(authenticationMono)
                .flatMap(oauthToken -> {
                    try {
                        return Mono.just(getEncryptedKey(oauthToken));
                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                });
    }

    public Mono<OAuth2AuthenticationToken> getOAuthToken(Mono<Authentication> authenticationMono) {
        return authenticationMono
                .filter(authentication ->
                        authentication.isAuthenticated()
                                && authentication instanceof OAuth2AuthenticationToken
                )
                .cast(OAuth2AuthenticationToken.class)
                .switchIfEmpty(Mono.error(
                        new ResponseStatusException(
                                HttpStatus.UNAUTHORIZED,
                                "User is not authenticated via OAuth2"
                        )
                ));
    }

    public Mono<CsrfToken> getCsrf(ServerWebExchange exchange) {
        // In WebFlux, the CsrfToken is extracted directly from the exchange attributes
        Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken : Mono.empty();
    }

    public Mono<Map<String, Object>> getAuthObject(Mono<Authentication> authenticationMono){
        // We use map() to process the authentication object only if it exists
        return authenticationMono.<Map<String, Object>>handle((authentication, sink) -> {
            Map<String, Object> response = new HashMap<>();

            boolean isRealUser = authentication.isAuthenticated()
                    && !(authentication instanceof AnonymousAuthenticationToken);

            if (isRealUser && authentication instanceof OAuth2AuthenticationToken) {
                OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
                OAuth2User principal = oauthToken.getPrincipal(); // Extract principal here
                String platform = oauthToken.getAuthorizedClientRegistrationId(); // e.g., "discord"

                String avatarUrl = null;
                if  (principal == null) {
                    response.put("authenticated", false);
                    sink.next(response);
                    return;
                }
                // the platform is discord, so discord hardcodes are made within
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

                    try {
                        String encrypted_key = getEncryptedKey(oauthToken);
                        response.put("ENCRYPTED_KEY", encrypted_key);
                    } catch (Exception e) {
                        // :::::::::::::::: IMPORTANT ::::::::::::::::::::::::
                        // failed to encrypt, this case needs to be studied
                        response.put("authenticated", false);
                    }
                }

                response.put("authenticated", true);
                response.put("username", principal.getAttribute("global_name"));
                response.put("platform", platform);
                response.put("avatarUrl", avatarUrl);

            } else {
                response.put("authenticated", false);
            }

            sink.next(response);

        }).defaultIfEmpty(Map.of("authenticated", false)); // Fallback if no auth context exists
    }

}