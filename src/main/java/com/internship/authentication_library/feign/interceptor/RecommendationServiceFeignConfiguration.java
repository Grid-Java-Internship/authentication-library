package com.internship.authentication_library.feign.interceptor;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(
        name = "security.feign.recommendation-service.enabled",
        havingValue = "true"
)
public class RecommendationServiceFeignConfiguration {

    @Value("${security.feign.recommendation-service.api-key}")
    private String apiKey;

    @Bean
    public RequestInterceptor apiKeyRequestInterceptor() {
        return new ApiKeyInterceptor(apiKey);
    }
}
