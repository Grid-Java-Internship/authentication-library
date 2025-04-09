package com.internship.authentication_library.config;

import com.internship.authentication_library.feign.AuthService;
import com.internship.authentication_library.filters.JwtFilter;
import com.internship.authentication_library.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class SecurityConfiguration {

    private final AuthService authService;

    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            String[] permittedRequestForAll,
            String[] permittedRequestForSuperAdmin,
            String[] permittedRequestForAdmin
    ) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(permittedRequestForAll).permitAll()
                        .requestMatchers(permittedRequestForSuperAdmin).hasRole("SUPER_ADMIN")
                        .requestMatchers(permittedRequestForAdmin).hasAnyRole("ADMIN","SUPER_ADMIN")
                        .anyRequest()
                        .authenticated()
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(new JwtFilter(new JwtUtil(authService)), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}

