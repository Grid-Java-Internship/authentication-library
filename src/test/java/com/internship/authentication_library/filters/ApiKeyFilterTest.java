package com.internship.authentication_library.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collection;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApiKeyFilterTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication existingAuthentication;

    @InjectMocks
    private ApiKeyFilter apiKeyFilter;

    private final String testApiKey = "test-secret-key-123";
    private MockHttpServletRequest mockRequest;
    private MockHttpServletResponse mockResponse;
    private StringWriter responseWriter;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(apiKeyFilter, "apiKey", testApiKey);
        mockRequest = new MockHttpServletRequest();
        mockResponse = new MockHttpServletResponse();
        responseWriter = new StringWriter();
        try {
            lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
        } catch (IOException e) {
            // No need to handle in mock setup usually
        }
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_shouldProceedWithoutAction_whenAuthenticationExists() throws ServletException, IOException {
        when(securityContext.getAuthentication()).thenReturn(existingAuthentication);

        apiKeyFilter.doFilterInternal(mockRequest, mockResponse, filterChain);

        verify(filterChain, times(1)).doFilter(mockRequest, mockResponse);
        verify(securityContext, times(1)).getAuthentication();
        verify(response, never()).setStatus(anyInt());
        verify(response, never()).getWriter();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(existingAuthentication);
    }

    @Test
    void doFilterInternal_shouldSetApiKeyAuthenticationAndProceed_whenValidApiKeyAndNoExistingAuth() throws ServletException, IOException {
        when(securityContext.getAuthentication()).thenReturn(null);
        mockRequest.addHeader(ApiKeyFilter.API_KEY_HEADER, testApiKey);

        apiKeyFilter.doFilterInternal(mockRequest, mockResponse, filterChain);

        ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
        verify(securityContext, times(1)).getAuthentication();
        verify(securityContext).setAuthentication(authenticationCaptor.capture());

        Authentication capturedAuth = authenticationCaptor.getValue();
        assertThat(capturedAuth).isNotNull();
        assertThat(capturedAuth.getPrincipal()).isEqualTo("api-key-principal");

        Collection<? extends GrantedAuthority> authorities = capturedAuth.getAuthorities();
        GrantedAuthority expectedAuthority = new SimpleGrantedAuthority("ROLE_API_KEY");

        assertEquals(expectedAuthority, authorities.iterator().next());

        assertThat(capturedAuth.isAuthenticated()).isTrue();

        verify(filterChain, times(1)).doFilter(mockRequest, mockResponse);
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    void doFilterInternal_shouldSetErrorResponseAndNotProceed_whenApiKeyHeaderIsInvalid() throws ServletException, IOException {
        when(securityContext.getAuthentication()).thenReturn(null);
        mockRequest.addHeader(ApiKeyFilter.API_KEY_HEADER, "invalid-key");

        apiKeyFilter.doFilterInternal(mockRequest, response, filterChain);

        verify(securityContext, times(1)).getAuthentication();
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain, never()).doFilter(any(), any());
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).setContentType("application/json");
        verify(response, times(3)).getWriter();
    }

    @Test
    void doFilterInternal_shouldSetErrorResponseAndNotProceed_whenApiKeyHeaderIsEmpty() throws ServletException, IOException {
        when(securityContext.getAuthentication()).thenReturn(null);
        mockRequest.addHeader(ApiKeyFilter.API_KEY_HEADER, "");

        apiKeyFilter.doFilterInternal(mockRequest, response, filterChain);

        verify(securityContext, times(1)).getAuthentication();
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain, never()).doFilter(any(), any());
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).setContentType("application/json");
        verify(response, times(3)).getWriter();
    }

    @Test
    void doFilterInternal_shouldThrowNullPointerException_whenRequestIsNull() {
        HttpServletResponse nonNullResponse = mock(HttpServletResponse.class);
        FilterChain nonNullFilterChain = mock(FilterChain.class);

        assertThrows(NullPointerException.class, () -> {
            apiKeyFilter.doFilterInternal(null, nonNullResponse, nonNullFilterChain);
        }, "Should throw NullPointerException when request is null due to @NonNull");

        verifyNoInteractions(nonNullFilterChain);
    }

    @Test
    void doFilterInternal_shouldThrowNullPointerException_whenResponseIsNull() {
        HttpServletRequest nonNullRequest = mock(HttpServletRequest.class);
        FilterChain nonNullFilterChain = mock(FilterChain.class);

        assertThrows(NullPointerException.class, () -> {
            apiKeyFilter.doFilterInternal(nonNullRequest, null, nonNullFilterChain);
        }, "Should throw NullPointerException when response is null due to @NonNull");

        verifyNoInteractions(nonNullFilterChain);
    }

    @Test
    void doFilterInternal_shouldThrowNullPointerException_whenFilterChainIsNull() {
        HttpServletRequest nonNullRequest = mock(HttpServletRequest.class);
        HttpServletResponse nonNullResponse = mock(HttpServletResponse.class);

        assertThrows(NullPointerException.class, () -> {
            apiKeyFilter.doFilterInternal(nonNullRequest, nonNullResponse, null);
        }, "Should throw NullPointerException when filterChain is null due to @NonNull");

        verifyNoInteractions(nonNullResponse);
    }
}
