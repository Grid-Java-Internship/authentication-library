package com.internship.authentication_library.feign.interceptor.payment_service;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.beans.factory.annotation.Value;

public class PaymentServiceInterceptor implements RequestInterceptor {

    private static final String API_KEY_HEADER = "X-API-KEY";

    @Value("${security.feign.payment-service.api-key}")
    private String apiKey;

    @Override
    public void apply(RequestTemplate template) {
        if (apiKey != null && !apiKey.isEmpty()) {
            template.header(API_KEY_HEADER, apiKey);
        }
    }
}