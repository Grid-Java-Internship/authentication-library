package com.internship.authentication_library.feign;

import com.internship.authentication_library.feign.interceptor.AuthServiceFeignConfiguration;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(
        name = "auth-service",
        url = "${microservicesUrls.auth-service}",
        configuration = AuthServiceFeignConfiguration.class
)
public interface AuthService {

    @GetMapping("/v1/auth/get_jwk/{kid}")
    String getPublicKey(@PathVariable("kid") String kid);

}
