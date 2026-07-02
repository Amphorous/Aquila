package org.hoyo.aquila.security.component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

// Runs before Spring Security (-100) to capture raw request headers before any filter modifies them.
// Remove this class once the CSRF issue is diagnosed.
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CsrfDebugFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(CsrfDebugFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest req = exchange.getRequest();
        String path = req.getURI().getPath();

        if ("/logout".equals(path) || "/csrf-token".equals(path)) {
            String method = req.getMethod().name();
            String headerToken = req.getHeaders().getFirst("X-XSRF-TOKEN");
            var cookieEntry = req.getCookies().getFirst("XSRF-TOKEN");
            String cookieToken = cookieEntry != null ? cookieEntry.getValue() : null;

            log.info("CSRF-DEBUG [{} {}] X-XSRF-TOKEN header: '{}' | XSRF-TOKEN cookie: '{}'",
                    method, path, headerToken, cookieToken);

            if ("/logout".equals(path) && "POST".equals(method)) {
                if (headerToken == null) {
                    log.warn("CSRF-DEBUG: X-XSRF-TOKEN header is MISSING on POST /logout");
                } else if (cookieToken == null) {
                    log.warn("CSRF-DEBUG: XSRF-TOKEN cookie is MISSING on POST /logout");
                } else if (headerToken.equals(cookieToken)) {
                    log.info("CSRF-DEBUG: header == cookie — tokens MATCH, CSRF should pass");
                } else {
                    log.warn("CSRF-DEBUG: header '{}' != cookie '{}' — MISMATCH, CSRF will FAIL",
                            headerToken, cookieToken);
                }
            }
        }

        return chain.filter(exchange);
    }
}
