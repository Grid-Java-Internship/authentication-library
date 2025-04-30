package com.internship.authentication_library.feign.interceptor;

import com.internship.authentication_library.filters.ApiKeyFilter;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ApiKeyInterceptor implements RequestInterceptor {

    private final String apiKey;

    @Override
    public void apply(RequestTemplate template) {
        if (apiKey != null && !apiKey.isEmpty()) {
            template.header(ApiKeyFilter.API_KEY_HEADER, apiKey);
        }
    }
}
