package com.internship.authentication_library.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class ApiKeyFilter extends OncePerRequestFilter {

    private static final String API_KEY_HEADER = "X-API-KEY";

    private static final String API_KEY_ROLE = "ROLE_API_KEY";

    @Value("${security.api-key}")
    private String apiKey;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if(SecurityContextHolder.getContext().getAuthentication() == null) {
            String actualApiKey = request.getHeader(API_KEY_HEADER);

            log.debug("Check API-KEY for path: {}", request.getRequestURI());

            if (!StringUtils.hasText(actualApiKey) || !apiKey.equals(actualApiKey)) {
                log.warn("Request rejected due to invalid or missing API key in header '{}'. " +
                        "Received key: '{}'", API_KEY_HEADER, actualApiKey);
                setErrorResponse(response, "Invalid or Missing API Key");
                return;
            }

            List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(API_KEY_ROLE));

            String principalName = "api-key-principal";

            UsernamePasswordAuthenticationToken apiKeyAuth = new UsernamePasswordAuthenticationToken(
                    principalName,
                    null,
                    authorities);

            apiKeyAuth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(apiKeyAuth);

            log.info("API-KEY authentication successful for path: {}", request.getRequestURI());
        }

        filterChain.doFilter(request, response);
    }

    private void setErrorResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{ \"error\": \"" + message + "\" }");
        response.getWriter().flush();
        response.getWriter().close();
    }
}

