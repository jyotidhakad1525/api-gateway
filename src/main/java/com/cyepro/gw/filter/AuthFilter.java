package com.cyepro.gw.filter;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.SerializationUtils;
import org.springframework.web.server.ServerWebExchange;

import com.cyepro.gw.config.JwtConfig;
import com.cyepro.gw.model.ErrorResponseDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;

@RefreshScope
@Component
@Slf4j
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {

	@Autowired
	private final RouterValidator routerValidator;
	private final JwtTokenUtil jwtTokenUtil;
	private final JwtConfig jwtConfig;

	public AuthFilter(RouterValidator routerValidator, JwtTokenUtil jwtTokenUtil, JwtConfig config) {
		super(Config.class);
		this.routerValidator = routerValidator;
		this.jwtTokenUtil = jwtTokenUtil;
		this.jwtConfig = config;
	}

	@Override
	public GatewayFilter apply(Config config) {
		return ((exchange, chain) -> {
			
			
			if (routerValidator.isSecured.test(exchange.getRequest()) && !jwtConfig.isAuthDisabled()) {
				if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
					List<String> details = new ArrayList<>();
					details.add("No Authorization Header");
					ErrorResponseDto error = new ErrorResponseDto(new Date(), HttpStatus.UNAUTHORIZED.value(), "UNAUTHORIZED", details, exchange.getRequest().getURI().toString());
					ServerHttpResponse response = exchange.getResponse();

					ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
					try {
						String json = ow.writeValueAsString(error);
						response.setStatusCode(HttpStatus.UNAUTHORIZED);
						DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(json.getBytes());
						return response.writeWith(Flux.just(buffer));
					} catch (JsonProcessingException e) {
						e.printStackTrace();
					}
					throw new RuntimeException("Missing Authorisation Header");
				}
				
				String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);
				try {
					Jws<Claims> validateToken = jwtTokenUtil.validateToken(authHeader);
					if(validateToken.getBody() != null) {
						Set<Entry<String,Object>> properties = validateToken.getBody().entrySet();
						if(properties != null && !properties.isEmpty()) {
							ServerWebExchange exchange1 = null;
							for (Entry<String, Object> entry : properties) {
								ServerHttpRequest request = exchange.getRequest()
						                .mutate()
						                .header(entry.getKey(), String.valueOf(entry.getValue()))
						                .build();
								exchange1 = exchange.mutate().request(request).build();
							}
							
							return chain.filter(exchange1);
						}
					}
				}
				catch (Exception ex) {
					log.error("Error Validating Authentication Header", ex.getMessage());
					List<String> details = new ArrayList<>();
					details.add(ex.getLocalizedMessage());
					ErrorResponseDto error = new ErrorResponseDto(new Date(), HttpStatus.UNAUTHORIZED.value(), "UNAUTHORIZED", details, exchange.getRequest().getURI().toString());
					ServerHttpResponse response = exchange.getResponse();

					ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
					try {
						String json = ow.writeValueAsString(error);
						response.setStatusCode(HttpStatus.UNAUTHORIZED);
						DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(json.getBytes());
						return response.writeWith(Flux.just(buffer));
					} catch (JsonProcessingException e) {
						log.error("Error in Exception block, while processing JSON", e);
					}
					
					return response.setComplete();
				}
			}
			
			return chain.filter(exchange);
		});
	}

	public static class Config {
	}
}
