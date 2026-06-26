package org.hoyo.aquila.security.component;

import lombok.RequiredArgsConstructor;
import org.hoyo.aquila.security.service.UserIdentityService;
import org.jspecify.annotations.NonNull;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class UserKeyForwardingFilter implements GlobalFilter {

    private final UserIdentityService userIdentityService;
    private final GatewayRequestSigner gatewayRequestSigner;

    // Forwards the authenticated user's key to downstream services, signed so they can
    // verify the request actually went through this gateway. Downstream services that
    // require this header (e.g. anything path-gated by "/protected") will reject
    // requests where the header is missing, malformed, or fails signature/timestamp
    // verification.
    @Override
    public @NonNull Mono<Void> filter(ServerWebExchange exchange, @NonNull GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .cast(OAuth2AuthenticationToken.class)
                .flatMap(auth -> {

                    String userKey = userIdentityService.getEncryptedKey(auth);
                    String timestamp = String.valueOf(Instant.now().toEpochMilli());
                    String signature = gatewayRequestSigner.sign(userKey, timestamp);

                    ServerHttpRequest request = exchange.getRequest()
                            .mutate()
                            .header("Aquila-User-Key", userKey)
                            .header("Aquila-Request-Timestamp", timestamp)
                            .header("Aquila-Signature", signature)
                            .build();

                    return chain.filter(
                            exchange.mutate()
                                    .request(request)
                                    .build()
                    );
                })
                .switchIfEmpty(chain.filter(exchange));
    }
}
