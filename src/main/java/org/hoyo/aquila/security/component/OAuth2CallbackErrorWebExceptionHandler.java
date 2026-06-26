package org.hoyo.aquila.security.component;

import org.hoyo.aquila.security.configuration.AppProperties;
import org.jspecify.annotations.NonNull;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * Spring Security's reactive OAuth2 client talks to Discord (token exchange + user-info) using
 * its own internal WebClient/Reactor Netty pipeline. When that fails with a low-level I/O error
 * (e.g. "Connection reset by peer" from a stale pooled connection), the resulting exception is
 * NOT an AuthenticationException, so it skips CustomOAuth2FailureHandler entirely and falls
 * through to the default error handler, rendering the Whitelabel Error Page.
 * <p>
 * Order(-2) runs this ahead of Boot's DefaultErrorWebExceptionHandler (Order(-1)) so any
 * unhandled exception thrown while processing the OAuth2 callback redirects back to the
 * frontend instead of showing a raw 500 page.
 */
@Component
@Order(-2)
public class OAuth2CallbackErrorWebExceptionHandler implements WebExceptionHandler {

    private static final String OAUTH2_CALLBACK_PATH_PREFIX = "/login/oauth2/code/";

    private final AppProperties appProperties;

    public OAuth2CallbackErrorWebExceptionHandler(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @Override
    public @NonNull Mono<Void> handle(ServerWebExchange exchange, @NonNull Throwable ex) {
        ServerHttpResponse response = exchange.getResponse();
        String path = exchange.getRequest().getPath().value();

        if (!path.startsWith(OAUTH2_CALLBACK_PATH_PREFIX) || response.isCommitted()) {
            return Mono.error(ex);
        }

        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(appProperties.getFrontendUrl().getHsr() + "?authError=true"));
        return response.setComplete();
    }
}
