package com.murkio.identity;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** A fake identity API for the tests: real Ed25519 keys, no network. */
final class FakeApi implements Transport {
    static final String KEY = "pk_java_test";

    final List<String> calls = new ArrayList<>();
    final Set<String> revoked = new HashSet<>();
    private final KeyPair pair;
    private final String jwks;
    private final String application;
    private final String issuer;

    FakeApi() throws Exception {
        this(null, "app-1", "enterprise-auth");
    }

    FakeApi(String jwks, String application, String issuer) throws Exception {
        this.pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded = pair.getPublic().getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        this.jwks = jwks != null
                ? jwks
                : "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"k1\",\"alg\":\"EdDSA\",\"x\":\"" + b64(raw)
                        + "\"}]}";
        this.application = application;
        this.issuer = issuer;
    }

    static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    @Override
    public Result send(String method, String url, Map<String, String> headers, String body) {
        String path = URI.create(url).getPath();
        calls.add(method + " " + path);
        switch (path) {
            case "/v1/client":
                if (!("Bearer " + KEY).equals(headers.get("Authorization"))) {
                    return new Result(401, "{\"details\":[{\"code\":\"bss-01\"}]}");
                }
                return new Result(
                        200,
                        "{\"data\":{\"application_id\":\"" + application + "\",\"issuer\":\"" + issuer
                                + "\",\"jwks_url\":\"/jwks.json\",\"config\":{},\"canvas\":{\"version\":0,\"document\":{\"note\":\"</script><b>&\\u2028\"}}}}");
            case "/jwks.json":
                return new Result(200, jwks);
            case "/v1/me":
                return new Result(
                        200,
                        "{\"data\":{\"id\":\"user-1\",\"session_id\":\"session-1\",\"email\":\"ana@example.com\",\"email_verified\":true,"
                                + "\"roles\":[\"user\"],\"mfa_enabled\":false,\"created_at\":\"2026-10-10T00:00:00Z\"}}");
            case "/v1/sessions/verify":
                String token = String.valueOf(Json.parseObject(body).get("access_token"));
                return new Result(200, "{\"data\":{\"active\":" + !revoked.contains(token) + "}}");
            default:
                return new Result(404, "{}");
        }
    }

    String token() throws Exception {
        return token(Map.of(), "k1");
    }

    String token(Map<String, Object> claims, String kid) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", issuer);
        payload.put("sub", "user-1");
        payload.put("aud", application);
        payload.put("aid", application);
        payload.put("sid", "session-1");
        payload.put("roles", List.of("user"));
        payload.put("iat", now);
        payload.put("exp", now + 900);
        payload.put("jti", "j1");
        payload.putAll(claims);
        String signing = b64(("{\"alg\":\"EdDSA\",\"kid\":\"" + kid + "\"}").getBytes(StandardCharsets.UTF_8)) + "."
                + b64(Json.write(payload).getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(pair.getPrivate());
        signer.update(signing.getBytes(StandardCharsets.US_ASCII));
        return signing + "." + b64(signer.sign());
    }

    Murkio client() {
        return Murkio.builder()
                .publishableKey(KEY)
                .apiUrl("https://api.example.com")
                .transport(this)
                .build();
    }
}
