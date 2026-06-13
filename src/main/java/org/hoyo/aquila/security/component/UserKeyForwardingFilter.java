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

@Component
@RequiredArgsConstructor
public class UserKeyForwardingFilter implements GlobalFilter {

    private final UserIdentityService userIdentityService;

    // MAKE SURE YOU ALWAYS ADD "/protected" TO PATHS YOU WANNA PROTECT
    @Override
    public @NonNull Mono<Void> filter(ServerWebExchange exchange, @NonNull GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!path.contains("protected")) {
            return chain.filter(exchange);
        }
        return exchange.getPrincipal()
                .cast(OAuth2AuthenticationToken.class)
                .flatMap(auth -> {

                    String userKey = userIdentityService.getEncryptedKey(auth);

                    ServerHttpRequest request = exchange.getRequest()
                            .mutate()
                            .header("Aquila-User-Key", userKey)
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