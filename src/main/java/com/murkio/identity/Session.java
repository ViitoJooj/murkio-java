package com.murkio.identity;

import java.util.List;
import java.util.Map;

/** A verified access token. */
public record Session(String userId, String sessionId, String applicationId, List<String> roles, Map<String, Object> claims, String token) {

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
