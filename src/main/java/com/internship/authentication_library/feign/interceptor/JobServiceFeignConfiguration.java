package com.internship.authentication_library.feign.interceptor;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(
        name = "security.feign.job-service.enabled",
        havingValue = "true"
)
public class JobServiceFeignConfiguration {

    @Value("${security.feign.job-service.api-key}")
    private String apiKey;

    @Bean("apiKeyRequestInterceptorJob")
    public RequestInterceptor apiKeyRequestInterceptor() {
        return new ApiKeyInterceptor(apiKey);
    }
}
