package com.murkio.identity;

import java.util.List;

/**
 * What a route asks of the request. Build with {@link #of()}:
 * {@code Options.of().required().signInUrl("/login").loadUser()}.
 */
public final class Options {
    boolean required;
    List<String> roles = List.of();
    String signInUrl = "";
    boolean handshake = true;
    boolean loadUser;
    boolean checkRevocation;

    private Options() {}

    public static Options of() {
        return new Options();
    }

    /** Answer 401 (or redirect browsers to the sign-in URL) when nobody is signed in. */
    public Options required() {
        this.required = true;
        return this;
    }

    /** Only sessions with one of these roles pass; others get 403. */
    public Options roles(String... roles) {
        this.roles = List.of(roles);
        return this;
    }

    /** Where browsers go when sign-in is required (the current path goes in ?redirect=). */
    public Options signInUrl(String url) {
        this.signInUrl = url == null ? "" : url;
        return this;
    }

    /** Turns off the page that refreshes an expired session cookie. */
    public Options noHandshake() {
        this.handshake = false;
        return this;
    }

    /** Also load the profile (POST /v1/me, cached a minute per session). */
    public Options loadUser() {
        this.loadUser = true;
        return this;
    }

    /** Ask the API whether the session was revoked (cached 30 s). */
    public Options checkRevocation() {
        this.checkRevocation = true;
        return this;
    }
}
