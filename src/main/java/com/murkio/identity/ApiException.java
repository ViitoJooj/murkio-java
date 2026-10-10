package com.murkio.identity;

/** An error answer of the identity API (status 0 when it could not be reached). */
public final class ApiException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int status;
    private final String code;

    public ApiException(int status, String code) {
        super("murkio: api answered " + status + " (" + code + ")");
        this.status = status;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }
}
