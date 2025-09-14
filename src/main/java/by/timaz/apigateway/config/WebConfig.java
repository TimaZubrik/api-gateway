package by.timaz.apigateway.config;

import org.springframework.cloud.client.loadbalancer.reactive.ReactorLoadBalancerExchangeFilterFunction;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebConfig {
    @Bean
    public WebClient webClient(ReactorLoadBalancerExchangeFilterFunction lb) {
        return WebClient.builder()
                .filter(lb)
                .build();
    }
}
