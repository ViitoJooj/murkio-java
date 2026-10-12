package com.murkio.identity;

/**
 * The outcome of {@link Murkio#protect}: who is signed in and, when the route
 * must not run, the response to send (null to go on).
 */
public record Protected(AuthResult result, Response response) {}
