package com.murkio.identity;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * What the SDK reads from an HTTP request. Header names are looked up without
 * case; {@code path} carries the query string.
 */
public record Request(
        String method,
        String scheme,
        String host,
        String path,
        Map<String, String> headers,
        Map<String, String> cookies) {

    public Request {
        Map<String, String> lower = new LinkedHashMap<>();
        headers.forEach((name, value) -> lower.put(name.toLowerCase(Locale.ROOT), value));
        headers = Map.copyOf(lower);
        cookies = Map.copyOf(cookies);
    }

    public String header(String name) {
        return headers.getOrDefault(name.toLowerCase(Locale.ROOT), "");
    }

    /** Parses a {@code Cookie} header (the first value of a repeated name wins). */
    public static Map<String, String> parseCookies(String header) {
        Map<String, String> cookies = new LinkedHashMap<>();
        if (header == null) {
            return cookies;
        }
        for (String part : header.split(";")) {
            int separator = part.indexOf('=');
            if (separator < 1) {
                continue;
            }
            String name = part.substring(0, separator).trim();
            String value = part.substring(separator + 1).trim();
            if (!name.isEmpty() && !value.isEmpty()) {
                cookies.putIfAbsent(name, value);
            }
        }
        return cookies;
    }
}
