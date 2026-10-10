package com.murkio.identity;

import java.util.Map;

/** An answer to send instead of running the route (401, 403, redirect or handshake). */
public record Response(int status, Map<String, String> headers, String body) {
}
