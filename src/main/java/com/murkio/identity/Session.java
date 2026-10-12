package com.murkio.identity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A verified access token. */
public record Session(
        String userId,
        String sessionId,
        String applicationId,
        List<String> roles,
        Map<String, Object> claims,
        String token) {

    /** The roles and the claims are copied: a session cannot be changed after it was verified. */
    public Session {
        roles = Collections.unmodifiableList(new ArrayList<>(roles));
        claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    /** True when the session has one of the roles. */
    public boolean hasRole(String... wanted) {
        for (String role : wanted) {
            if (roles.contains(role)) {
                return true;
            }
        }
        return false;
    }
}
