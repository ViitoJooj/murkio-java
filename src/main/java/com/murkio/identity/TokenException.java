package com.murkio.identity;

/** The access token was refused. {@link #reason()} is {@code invalid} or {@code expired}. */
public final class TokenException extends Exception {
    private static final long serialVersionUID = 1L;

    private final String reason;

    public TokenException(String message, String reason) {
        super(message);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
