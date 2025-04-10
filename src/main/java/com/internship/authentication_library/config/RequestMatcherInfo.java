package com.internship.authentication_library.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpMethod;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RequestMatcherInfo {
    private HttpMethod method;
    private String pattern;
}
