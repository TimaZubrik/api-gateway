package by.timaz.apigateway.filter;

import by.timaz.apigateway.dto.AuthResponse;
import by.timaz.apigateway.exception.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    private final WebClient webClient;
    private final static String REFRESH_HEADER="X-Refresh-Token";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             GatewayFilterChain chain) {

        var path = exchange.getRequest()
                           .getPath()
                           .toString();

        if (path.startsWith("/auth")) {
            return chain.filter(exchange);
        }

        String access = exchange.getRequest()
                                .getHeaders()
                                .getFirst(HttpHeaders.AUTHORIZATION);
        String refresh = exchange.getRequest()
                                 .getHeaders()
                                 .getFirst(REFRESH_HEADER);

        if (access == null || refresh == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
         return validateAccess(access)
                 .then(chain.filter(exchange))
                 .onErrorResume(AuthException.class,
                         ex -> refreshTokens(exchange, chain, access, refresh));
    }
    private Mono<Void> validateAccess(String bearerToken) {
        return webClient.get()
                .uri("http://auth-service/auth/test")
                .header(HttpHeaders.AUTHORIZATION, bearerToken)
                .retrieve()
                .onStatus(
                        status -> status == HttpStatus.UNAUTHORIZED,
                        resp -> Mono.error(new AuthException("Access expired"))
                )
                .toBodilessEntity()
                .then();
    }
    private Mono<Void> refreshTokens(ServerWebExchange exchange,
                                     GatewayFilterChain chain,
                                     String access,
                                     String refresh) {
        return webClient.post()
                .uri("http://auth-service/auth/refresh")
                .header(HttpHeaders.AUTHORIZATION, access)
                .header(REFRESH_HEADER, refresh)
                .retrieve()
                .onStatus(status ->status == HttpStatus.UNAUTHORIZED,
                        response -> Mono.error(new AuthException("Refresh")))
                .bodyToMono(AuthResponse.class)
                .flatMap(auth -> {
                        ServerHttpRequest mutated = exchange.getRequest()
                                .mutate()
                                .header(HttpHeaders.AUTHORIZATION,"Bearer "+auth.getAccessToken())
                                .header(REFRESH_HEADER,auth.getRefreshToken())
                                .build();

                        exchange.getResponse().getHeaders()
                                .set(HttpHeaders.AUTHORIZATION, "Bearer " + auth.getAccessToken());
                        exchange.getResponse().getHeaders()
                                .set(REFRESH_HEADER, auth.getRefreshToken());

                   return chain.filter(exchange.mutate()
                           .request(mutated)
                           .build());
                })
                .onErrorResume(AuthException.class, ex ->{
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }
    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE;
    }
}
