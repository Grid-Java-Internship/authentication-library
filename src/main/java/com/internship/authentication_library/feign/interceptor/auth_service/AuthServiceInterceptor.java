package com.internship.authentication_library.feign.interceptor.auth_service;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.beans.factory.annotation.Value;

public class AuthServiceInterceptor implements RequestInterceptor {

    private static final String API_KEY_HEADER = "X-API-KEY";

    @Value("${security.feign.auth-service}")
    private String apiKey;

    @Override
    public void apply(RequestTemplate template) {
        if (apiKey != null && !apiKey.isEmpty()) {
            template.header(API_KEY_HEADER, apiKey);
        }
    }
}
