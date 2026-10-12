package com.murkio.identity.servlet;

import com.murkio.identity.AuthResult;
import com.murkio.identity.Murkio;
import com.murkio.identity.Options;
import com.murkio.identity.Protected;
import com.murkio.identity.Request;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A servlet filter (Jakarta Servlet 5+, Spring Boot 3+): puts the
 * {@link AuthResult} in the request attribute {@code murkio} and answers 401,
 * 403, a redirect or the handshake page according to the options.
 *
 * <pre>{@code
 * @Bean
 * FilterRegistrationBean<MurkioFilter> murkioFilter(Murkio murkio) {
 *     var bean = new FilterRegistrationBean<>(new MurkioFilter(murkio, Options.of().required().signInUrl("/login")));
 *     bean.addUrlPatterns("/dashboard/*");
 *     return bean;
 * }
 *
 * AuthResult auth = MurkioFilter.get(request);   // .session(), .user()
 * }</pre>
 */
public final class MurkioFilter implements Filter {
    public static final String ATTRIBUTE = "murkio";

    private final Murkio murkio;
    private final Options options;

    public MurkioFilter(Murkio murkio, Options options) {
        this.murkio = murkio;
        this.options = options;
    }

    /** The result the filter stored, or an empty one when the filter did not run. */
    public static AuthResult get(ServletRequest request) {
        Object value = request.getAttribute(ATTRIBUTE);
        return value instanceof AuthResult result ? result : new AuthResult(null, null, "missing", false);
    }

    /** The request fields the SDK reads, from a servlet request. */
    public static Request toRequest(HttpServletRequest request) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (String name : Collections.list(request.getHeaderNames())) {
            headers.put(name, request.getHeader(name));
        }
        String host = request.getHeader("Host");
        if (host == null || host.isEmpty()) {
            host = request.getServerName();
        }
        String query = request.getQueryString();
        String path = request.getRequestURI() + (query == null || query.isEmpty() ? "" : "?" + query);
        return new Request(
                request.getMethod(),
                request.getScheme(),
                host,
                path,
                headers,
                Request.parseCookies(request.getHeader("Cookie")));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest http) || !(response instanceof HttpServletResponse answer)) {
            chain.doFilter(request, response);
            return;
        }

        Protected outcome = murkio.protect(toRequest(http), options);
        request.setAttribute(ATTRIBUTE, outcome.result());
        if (outcome.response() == null) {
            chain.doFilter(request, response);
            return;
        }

        answer.setStatus(outcome.response().status());
        outcome.response().headers().forEach(answer::setHeader);
        answer.getOutputStream().write(outcome.response().body().getBytes(StandardCharsets.UTF_8));
    }
}
