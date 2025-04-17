package com.internship.authentication_library.feign.interceptor.payment_service;

import feign.RequestInterceptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PaymentServiceFeignConfiguration {

    @Bean
    @ConditionalOnProperty(
            name = "security.feign.payment-service.enabled",
            havingValue = "true"
    )
    public RequestInterceptor apiKeyRequestInterceptor() {
        return new PaymentServiceInterceptor();
    }
}
