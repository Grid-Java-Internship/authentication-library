package com.internship.authentication_library.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "auth-service", url = "${microservicesUrls.auth-service}")
public interface AuthService {

    @GetMapping("/v1/auth/get_jwk")
    String getPublicKey();

}
