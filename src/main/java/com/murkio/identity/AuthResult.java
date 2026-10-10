package com.murkio.identity;

/**
 * Who is behind a request.
 *
 * @param session      null when nobody is signed in
 * @param user         the profile, when it was asked for
 * @param reason       why there is no session: missing, invalid, expired, revoked or csrf
 * @param signedInHint the browser holds a session, even if this request's token is missing or expired
 */
public record AuthResult(Session session, User user, String reason, boolean signedInHint) {

    public boolean signedIn() {
        return session != null;
    }
}
