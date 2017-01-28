package com.boris.reservations.zuul.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import feign.Request;

@Configuration
public class CustomFeignConfig {
	
	public static final int FIVE_SECONDS = 5000;

	@Bean
    public Request.Options options() {
        return new Request.Options(FIVE_SECONDS, FIVE_SECONDS);
    }
}
