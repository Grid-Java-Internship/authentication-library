package com.internship.authentication_library.filters;

import com.internship.authentication_library.util.JwtUtil;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.text.ParseException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER_STRING = "Authorization";
    private static final String AUTH_TOKEN_PREFIX = "Bearer ";
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String header = request.getHeader(AUTH_HEADER_STRING);
        final String jwtToken;
        final String email;

        if (header == null || !header.startsWith(AUTH_TOKEN_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }
        jwtToken = header.substring(AUTH_TOKEN_PREFIX.length());

        try {
            if (jwtUtil.validateToken(jwtToken)) {
                email = jwtUtil.extractEmail(jwtToken);

                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = jwtUtil.extractUserDTO(jwtToken);

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails.getUsername(),
                            userDetails.getPassword(),
                            userDetails.getAuthorities()
                    );

                    authenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
                else {
                    setErrorResponse(response, "There was an issue with reading the token.");
                    return;
                }

            } else {
                setErrorResponse(response, "JWT is invalid or expired.");
                return;
            }
        } catch (ParseException | JOSEException e) {
            setErrorResponse(response, "There was an issue with reading the token.");
            return;
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
