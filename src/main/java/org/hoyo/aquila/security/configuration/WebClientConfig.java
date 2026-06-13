package org.hoyo.aquila.security.configuration;

import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.time.Duration;

@Configuration
public class WebClientConfig {

    // Discord/Cloudflare close idle connections well within an hour. Reactor Netty's default pool
    // never evicts idle connections on its own, so a connection opened during the first login can
    // go stale and blow up with "Connection reset by peer" the next time it is reused (e.g. the
    // token exchange on the next login).
    private static final Duration MAX_IDLE_TIME = Duration.ofSeconds(45);

    @Bean
    public ReactorClientHttpConnector reactorClientHttpConnector() {
        ConnectionProvider connectionProvider = ConnectionProvider.builder("aquila-http-pool")
                .maxIdleTime(MAX_IDLE_TIME)
                .evictInBackground(MAX_IDLE_TIME)
                .build();

        return new ReactorClientHttpConnector(HttpClient.create(connectionProvider));
    }

    @Bean
    @LoadBalanced
    public WebClient.Builder webClientBuilder(ReactorClientHttpConnector reactorClientHttpConnector) {
        return WebClient.builder().clientConnector(reactorClientHttpConnector);
    }

    // Spring Security builds its OAuth2 token-exchange and user-info clients with a bare
    // WebClient.create(), bypassing the connector above entirely. These beans are picked up
    // automatically by the reactive OAuth2 login DSL (matched by generic type), and are the only
    // way to apply the same idle-connection eviction to the calls made to Discord during login.
    @Bean
    public ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oauth2AccessTokenResponseClient(
            ReactorClientHttpConnector reactorClientHttpConnector) {
        WebClientReactiveAuthorizationCodeTokenResponseClient client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
        client.setWebClient(WebClient.builder().clientConnector(reactorClientHttpConnector).build());
        return client;
    }

    @Bean
    public ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(
            ReactorClientHttpConnector reactorClientHttpConnector) {
        DefaultReactiveOAuth2UserService service = new DefaultReactiveOAuth2UserService();
        service.setWebClient(WebClient.builder().clientConnector(reactorClientHttpConnector).build());
        return service;
    }
}
