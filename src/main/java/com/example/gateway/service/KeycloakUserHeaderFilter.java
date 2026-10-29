package com.example.gateway.service;

import org.jspecify.annotations.NonNull;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class KeycloakUserHeaderFilter implements GlobalFilter {

    private static final String AUTHORIZATION_HEADER = HttpHeaders.AUTHORIZATION;
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String X_USER_LOGIN_HEADER = "X-User-Login";
    private static final String KEYCLOAK_USERNAME_CLAIM = "preferred_username";

    private final ReactiveJwtDecoder reactiveJwtDecoder;

    public KeycloakUserHeaderFilter(ReactiveJwtDecoder reactiveJwtDecoder) {
        this.reactiveJwtDecoder = reactiveJwtDecoder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, @NonNull GatewayFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange);
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        if (token.isBlank()) {
            return unauthorized(exchange);
        }

        return reactiveJwtDecoder.decode(token)
                .flatMap(jwt -> {
                    String username = jwt.getClaimAsString(KEYCLOAK_USERNAME_CLAIM);

                    if (username == null || username.isBlank()) {
                        return unauthorized(exchange);
                    }

                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(request -> request.headers(
                                    headers -> {
                                        headers.remove(X_USER_LOGIN_HEADER);
                                        headers.set(X_USER_LOGIN_HEADER, username);
                                    })
                            )
                            .build();
                    return chain.filter(mutatedExchange);
                })
                .onErrorResume(exception -> unauthorized(exchange));
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
