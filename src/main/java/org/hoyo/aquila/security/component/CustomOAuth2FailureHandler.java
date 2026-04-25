package org.hoyo.aquila.security.component;

// Be sure to import your AppProperties from wherever it is located in your project
// import org.hoyo.aquila.security.AppProperties;

import org.hoyo.aquila.security.configuration.AppProperties;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
public class CustomOAuth2FailureHandler implements ServerAuthenticationFailureHandler {

    private final AppProperties appProperties;

    public CustomOAuth2FailureHandler(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @Override
    public @NonNull Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, @NonNull AuthenticationException exception) {
        ServerHttpResponse response = webFilterExchange.getExchange().getResponse();

        response.setStatusCode(HttpStatus.FOUND);

        String redirectUrl = appProperties.getFrontendUrl().getHsr();
        response.getHeaders().setLocation(URI.create(redirectUrl));

        return response.setComplete();
    }
}