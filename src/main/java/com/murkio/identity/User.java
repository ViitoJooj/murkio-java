package com.murkio.identity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** The profile of {@code POST /v1/me}. {@code email} is null for a user without a primary email. */
public record User(
        String id,
        String sessionId,
        String email,
        boolean emailVerified,
        List<String> roles,
        boolean mfaEnabled,
        String createdAt) {

    /** The roles are copied: a profile cannot be changed after it was read. */
    public User {
        roles = Collections.unmodifiableList(new ArrayList<>(roles));
    }
}
