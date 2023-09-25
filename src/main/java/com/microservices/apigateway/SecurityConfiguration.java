package com.microservices.apigateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfiguration {

    private final JwtAuthSecurityFilter jwtAuthSecurityFilter;



    @Autowired
    public SecurityConfiguration(JwtAuthSecurityFilter jwtAuthSecurityFilter) {
        this.jwtAuthSecurityFilter = jwtAuthSecurityFilter;

    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager() {
        return authentication -> Mono.empty();
    }

/*
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    SecurityWebFilterChain webHttpSecurity(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange((exchanges) -> exchanges
                        .pathMatchers("/api/auth/**").permitAll()
                        .anyExchange().authenticated())
                .addFilterAt(jwtAuthSecurityFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }
*/


    @Bean

    SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) {
        http.csrf(csrf -> csrf.disable())
                .cors().disable()
                .authorizeExchange()
                .pathMatchers("/files").authenticated()
                .anyExchange().permitAll()
                .and()
                .addFilterAt(jwtAuthSecurityFilter,SecurityWebFiltersOrder.AUTHENTICATION);
        return http.build();
    }



}