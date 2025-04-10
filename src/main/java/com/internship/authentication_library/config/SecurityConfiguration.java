package com.internship.authentication_library.config;

import com.internship.authentication_library.filters.JwtFilter;
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

    private final JwtFilter jwtFilter;

    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            String[] permittedRequestForAll,
            String[] permittedRequestForSuperAdmin,
            String[] permittedRequestForAdmin
    ) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(permittedRequestForSuperAdmin).hasRole("SUPER_ADMIN")
                        .requestMatchers(permittedRequestForAdmin).hasAnyRole("ADMIN","SUPER_ADMIN")
                        .requestMatchers(permittedRequestForAll)
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}

