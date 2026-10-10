package com.murkio.identity;

import java.util.Map;

/** Sends an HTTP request to the identity API. The default uses {@code java.net.http}. */
@FunctionalInterface
public interface Transport {

    /** The status and body of an HTTP answer. */
    record Result(int status, String body) {
    }

    Result send(String method, String url, Map<String, String> headers, String body) throws Exception;
}
