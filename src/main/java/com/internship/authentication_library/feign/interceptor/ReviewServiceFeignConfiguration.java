package com.internship.authentication_library.feign.interceptor;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@ConditionalOnProperty(
        name = "security.feign.review-service.enabled",
        havingValue = "true"
)
public class ReviewServiceFeignConfiguration {

    @Value("${security.feign.review-service.api-key}")
    private String apiKey;

    @Bean("apiKeyRequestInterceptorReview")
    public RequestInterceptor apiKeyRequestInterceptor() {
        return new ApiKeyInterceptor(apiKey);
    }
}
