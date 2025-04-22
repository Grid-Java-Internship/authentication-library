package com.internship.authentication_library.feign.interceptor;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ApiKeyInterceptor implements RequestInterceptor {

    private static final String API_KEY_HEADER = "X-API-KEY";
    private final String apiKey;

    @Override
    public void apply(RequestTemplate template) {
        if (apiKey != null && !apiKey.isEmpty()) {
            template.header(API_KEY_HEADER, apiKey);
        }
    }
}
