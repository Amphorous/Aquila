package org.hoyo.aquila.security.configuration;

import org.hoyo.aquila.security.component.CustomOAuth2FailureHandler;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.List;

// Backs reactive WebSessions with Redis instead of the default in-memory store - the
// OAuth2Authentication and Discord OAuth2AuthorizedClient live inside the WebSession, so an
// in-memory store (30 min default idle timeout, wiped on every restart) was silently logging
// users out. 604_800s = 7 days, matching how long Discord access tokens stay usable.
@EnableRedisWebSession(maxInactiveIntervalInSeconds = 604_800)
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final CustomOAuth2FailureHandler failureHandler;
    private final AppProperties appProperties;

    // Injecting both the failure handler and your dynamic properties
    public SecurityConfig(CustomOAuth2FailureHandler failureHandler,  AppProperties appProperties) {
        this.failureHandler = failureHandler;
        this.appProperties = appProperties;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                // Configure reactive CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Configure reactive CSRF with cookie token repository.
                // ServerCsrfTokenRequestAttributeHandler (non-XOR) is required when using
                // CookieServerCsrfTokenRepository — the default XOR handler (Spring Security 6+)
                // is incompatible with the Angular double-submit cookie pattern.
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler())
                )

                // authorizeExchange instead of authorizeHttpRequests
                .authorizeExchange(auth -> auth
                        .pathMatchers("/api/auth/status", "/csrf-token", "/logout").permitAll()
                        .anyExchange().permitAll()
                )

                // Reactive OAuth2 configuration
                .oauth2Login(oauth2 -> oauth2
                        // Using AppProperties for the dynamic success redirect URL
                        .authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler(appProperties.getLoginSuccessUrl().getHsr()))
                        .authenticationFailureHandler(failureHandler)
                )

                // Reactive Logout configuration
                .logout(logout -> logout
                        .logoutSuccessHandler((webFilterExchange, authentication) -> {
                            // Set HTTP 200 OK status on successful logout
                            webFilterExchange.getExchange().getResponse().setStatusCode(HttpStatus.OK);
                            // Return an empty Mono to complete the reactive stream
                            return Mono.empty();
                        })
                );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Dynamically pull the frontend origin from application.properties
        configuration.setAllowedOrigins(List.of(appProperties.getFrontendUrl().getHsr()));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        // Ensure this is org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}