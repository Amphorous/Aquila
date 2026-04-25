package org.hoyo.aquila.security.configuration;

import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
@ConfigurationProperties(prefix = "application")
public class AppProperties {

    // These map to application.frontendUrl and application.loginSuccessUrl
    private final RouteConfig frontendUrl = new RouteConfig();
    private final RouteConfig loginSuccessUrl = new RouteConfig();
    private final RouteConfig loginFailureUrl = new RouteConfig();

    // Nested class that holds the 'hsr' variable.
    // If you ever add '.genshin' or '.zzz' later, you just add them as strings here.
    @Data
    public static class RouteConfig {
        private String hsr;
    }
}