package org.hoyo.aquila.security;

import lombok.RequiredArgsConstructor;
import org.hoyo.aquila.security.service.BinderService;
import org.hoyo.aquila.security.service.UserIdentityService;
import org.hoyo.aquila.security.service.UserRegistryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Set;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserIdentityService userIdentityService;
    private final BinderService binderService;
    private final UserRegistryService userRegistryService;

    @GetMapping("/api/auth/status")
    public Mono<Map<String, Object>> authStatus(Mono<Authentication> authenticationMono) {
        return userIdentityService.getAuthObject(authenticationMono);
    }

    @GetMapping("/csrf-token")
    public Mono<Map<String, String>> csrf(ServerWebExchange exchange) {
        return userIdentityService.getCsrf(exchange)
                .map(token -> {
                    // CsrfWebFilter's deferred saveToken() is not reliably called in this
                    // Spring Cloud Gateway + forward-headers setup, so we set the cookie explicitly.
                    boolean secure = "https".equals(exchange.getRequest().getURI().getScheme());
                    exchange.getResponse().addCookie(
                            ResponseCookie.from("XSRF-TOKEN", token.getToken())
                                    .httpOnly(false)
                                    .secure(secure)
                                    .path("/")
                                    .sameSite("Lax")
                                    .build()
                    );
                    log.info("CSRF-DEBUG /csrf-token explicitly set XSRF-TOKEN cookie (secure={}): '{}'",
                            secure, token.getToken());
                    return Map.of("token", token.getToken());
                });
    }

    @GetMapping("api/binding-code/generate")
    public Mono<String> generateBindingCode(Mono<Authentication> authenticationMono, String game, String uid) {
        return userIdentityService.getEncryptedKeyMono(authenticationMono)
                .flatMap(encrypted_key ->
                        binderService.generateBindingCode(encrypted_key, game, uid)
                );
    }

    @GetMapping("api/binding-code/verify")
    public Mono<Boolean> verifyBindingCode(Mono<Authentication> authenticationMono, String game, String uid) {
        return userIdentityService.getEncryptedKeyMono(authenticationMono)
                .flatMap(encrypted_key ->
                        binderService.verifyBinding(encrypted_key, game, uid)
                );
    }

    @GetMapping("api/binding-code/get-bindings")
    public Mono<Map<String, Set<String>>> getUserMappings(Mono<Authentication> authenticationMono){
        return userIdentityService.getEncryptedKeyMono(authenticationMono)
                .flatMap(userRegistryService::getUserGameMappings);
    }
}