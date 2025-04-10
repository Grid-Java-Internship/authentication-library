package com.internship.authentication_library.config;

import com.internship.authentication_library.filters.JwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor
@Component
public class SecurityConfiguration {

    private final JwtFilter jwtFilter;

    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            List<RequestMatcherInfo> permittedRequestForAll,
            List<RequestMatcherInfo> permittedRequestForSuperAdmin,
            List<RequestMatcherInfo> permittedRequestForAdmin
    ) throws Exception {

        RequestMatcher[] matchersForAll = convertToRequestMatchers(permittedRequestForAll);
        RequestMatcher[] matchersForSuperAdmin = convertToRequestMatchers(permittedRequestForSuperAdmin);
        RequestMatcher[] matchersForAdmin = convertToRequestMatchers(permittedRequestForAdmin);


        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(matchersForSuperAdmin).hasRole("SUPER_ADMIN")
                        .requestMatchers(matchersForAdmin).hasAnyRole("ADMIN","SUPER_ADMIN")
                        .requestMatchers(matchersForAll)
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }



    private RequestMatcher[] convertToRequestMatchers(List<RequestMatcherInfo> requests) {
        if (requests == null || requests.isEmpty()) {
            return new RequestMatcher[0];
        }
        return requests.stream()
                .map(info -> new AntPathRequestMatcher(info.getPattern(), info.getMethod().name()))
                .toArray(RequestMatcher[]::new);
    }

}

