package com.murkio.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.murkio.identity.servlet.MurkioFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MurkioFilterTest {

    /** A servlet request and response made of dynamic proxies: only what the filter touches. */
    private static final class Exchange {
        final Map<String, Object> attributes = new HashMap<>();
        final Map<String, String> responseHeaders = new HashMap<>();
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        int status = 200;
        boolean chained;
        final HttpServletRequest request;
        final HttpServletResponse response;

        Exchange(String uri, Map<String, String> headers) {
            request = (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {HttpServletRequest.class}, (proxy, method, args) -> switch (method.getName()) {
                case "getMethod" -> "GET";
                case "getScheme" -> "https";
                case "getServerName" -> "app.example.com";
                case "getRequestURI" -> uri;
                case "getQueryString" -> null;
                case "getHeaderNames" -> Collections.enumeration(headers.keySet());
                case "getHeader" -> headers.get((String) args[0]);
                case "getAttribute" -> attributes.get((String) args[0]);
                case "setAttribute" -> attributes.put((String) args[0], args[1]);
                default -> null;
            });
            ServletOutputStream stream = new ServletOutputStream() {
                @Override
                public void write(int b) {
                    body.write(b);
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setWriteListener(WriteListener listener) {
                }
            };
            response = (HttpServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {HttpServletResponse.class}, (proxy, method, args) -> {
                switch (method.getName()) {
                    case "setStatus" -> status = (Integer) args[0];
                    case "setHeader" -> responseHeaders.put((String) args[0], (String) args[1]);
                    case "getOutputStream" -> {
                        return stream;
                    }
                    default -> {
                    }
                }
                return null;
            });
        }

        void run(MurkioFilter filter) throws Exception {
            FilterChain chain = (req, res) -> chained = true;
            filter.doFilter(request, response, chain);
        }
    }

    @Test
    void filter() throws Exception {
        FakeApi api = new FakeApi();
        MurkioFilter filter = new MurkioFilter(api.client(), Options.of().required().signInUrl("/login"));

        Exchange denied = new Exchange("/api/orders", Map.of("Host", "app.example.com"));
        denied.run(filter);
        assertEquals(401, denied.status);
        assertEquals(false, denied.chained);
        assertNull(MurkioFilter.get(denied.request).session());

        Exchange page = new Exchange("/dashboard", Map.of("Host", "app.example.com", "Accept", "text/html"));
        page.run(filter);
        assertEquals(302, page.status);
        assertEquals("/login?redirect=%2Fdashboard", page.responseHeaders.get("Location"));

        Exchange allowed = new Exchange("/api/orders", Map.of("Host", "app.example.com", "Authorization", "Bearer " + api.token()));
        allowed.run(filter);
        assertEquals(true, allowed.chained);
        assertEquals("user-1", MurkioFilter.get(allowed.request).session().userId());
    }
}
