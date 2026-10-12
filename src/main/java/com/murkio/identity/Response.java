package com.murkio.identity;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** An answer to send instead of running the route (401, 403, redirect or handshake). */
public record Response(int status, Map<String, String> headers, String body) {

    /** The headers are copied, in the same order: an answer cannot be changed after it was built. */
    public Response {
        headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }
}
