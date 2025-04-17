package com.internship.authentication_library.feign.interceptor.auth_service;

import feign.RequestInterceptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthServiceFeignConfiguration {

    @Bean
    @ConditionalOnProperty(
            name = "security.feign.auth-service.enabled",
            havingValue = "true"
    )
    public RequestInterceptor apiKeyRequestInterceptor() {
        return new AuthServiceInterceptor();
    }
}
