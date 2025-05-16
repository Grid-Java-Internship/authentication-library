package com.internship.authentication_library.config;

import com.internship.authentication_library.filters.ApiKeyFilter;
import com.internship.authentication_library.filters.JwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
@ConditionalOnProperty(
        name = "security.jwt.enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class SecurityConfiguration {

    private final JwtFilter jwtFilter;
    private final ApiKeyFilter apiKeyFilter;
    private static final String ADMIN_ROLE="ADMIN";
    private static final String USER_ROLE="USER";
    private static final String SUPER_ADMIN_ROLE="SUPER_ADMIN";
    private static final String API_KEY_ROLE="API_KEY";

    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            List<RequestMatcherInfo> permittedRequestForAll,
            List<RequestMatcherInfo> permittedRequestForSuperAdmin,
            List<RequestMatcherInfo> permittedRequestForAdminOrSuperAdmin,
            List<RequestMatcherInfo> permittedRequestForUsersOrAdminOrSuperAdmin
    ) throws Exception {

        RequestMatcher[] matchersForAll = convertToRequestMatchers(permittedRequestForAll);
        RequestMatcher[] matchersForSuperAdmin = convertToRequestMatchers(permittedRequestForSuperAdmin);
        RequestMatcher[] matchersForAdminOrSuperAdmin = convertToRequestMatchers(permittedRequestForAdminOrSuperAdmin);
        RequestMatcher[] matchersForUsersOrAdminOrSuperAdmin= convertToRequestMatchers(permittedRequestForUsersOrAdminOrSuperAdmin);


        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(matchersForSuperAdmin).hasAnyRole(SUPER_ADMIN_ROLE, API_KEY_ROLE)
                        .requestMatchers(matchersForAdminOrSuperAdmin).hasAnyRole(ADMIN_ROLE,SUPER_ADMIN_ROLE, API_KEY_ROLE)
                        .requestMatchers(matchersForUsersOrAdminOrSuperAdmin).hasAnyRole(USER_ROLE,ADMIN_ROLE,SUPER_ADMIN_ROLE, API_KEY_ROLE)
                        .requestMatchers(matchersForAll).permitAll()
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(apiKeyFilter, JwtFilter.class);

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

