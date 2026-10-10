package com.murkio.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class MurkioTest {
    private static final String HASH = Murkio.fnv1a32(FakeApi.KEY);
    private static final Map<String, String> PAGE = Map.of("Accept", "text/html", "Sec-Fetch-Mode", "navigate");

    private static Request request(String method, Map<String, String> headers, Map<String, String> cookies) {
        return new Request(method, "https", "app.example.com", "/", headers, cookies);
    }

    private static Request path(String path, Map<String, String> headers, Map<String, String> cookies) {
        return new Request("GET", "https", "app.example.com", path, headers, cookies);
    }

    /** The same tokens must get the same verdict in every server SDK (libs/spec/server). */
    @Test
    @SuppressWarnings("unchecked")
    void sharedVectors() throws Exception {
        Map<String, Object> vectors = Json.parseObject(Files.readString(Path.of("..", "..", "spec", "server", "vectors.json")));
        ((Map<String, Object>) vectors.get("cookie_hash")).forEach((value, expected) -> assertEquals(expected, Murkio.fnv1a32(value)));

        for (Object item : (List<Object>) vectors.get("cases")) {
            Map<String, Object> tc = (Map<String, Object>) item;
            String name = String.valueOf(tc.get("name"));
            Murkio client = new FakeApi(Json.write(vectors.get("jwks")), String.valueOf(vectors.get("application_id")), String.valueOf(vectors.get("issuer"))).client();
            String verdict = "valid";
            Session session = null;
            try {
                session = client.verify(String.valueOf(tc.get("token")));
            } catch (TokenException refused) {
                verdict = refused.reason().equals("expired") ? "expired" : "rejected";
            }
            assertEquals(tc.get("expect"), verdict, name);
            if (session != null) {
                Map<String, Object> expected = (Map<String, Object>) tc.get("session");
                assertEquals(expected.get("user_id"), session.userId(), name);
                assertEquals(expected.get("session_id"), session.sessionId(), name);
                assertEquals(expected.get("roles"), session.roles(), name);
            }
        }
    }

    @Test
    void refusesSecretKeys() {
        assertThrows(IllegalArgumentException.class, () -> Murkio.builder().publishableKey("sk_secret").build());
    }

    @Test
    void bootstrapAndJwksAreFetchedOnce() throws Exception {
        FakeApi api = new FakeApi();
        Murkio client = api.client();
        client.verify(api.token());
        client.verify(api.token());
        assertThrows(TokenException.class, () -> client.verify(api.token(Map.of(), "rotated")));
        assertEquals(List.of("GET /v1/client", "GET /jwks.json"), api.calls);
    }

    @Test
    void bearerTokenAndApiKeys() throws Exception {
        FakeApi api = new FakeApi();
        Murkio client = api.client();
        String token = api.token(Map.of("roles", List.of("admin")), "k1");
        AuthResult result = client.authenticate(request("GET", Map.of("Authorization", "Bearer " + token), Map.of()), Options.of());
        assertEquals("user-1", result.session().userId());
        assertTrue(result.session().hasRole("admin"));
        assertEquals("missing", client.authenticate(request("GET", Map.of("authorization", "Bearer " + FakeApi.KEY), Map.of()), Options.of()).reason());
    }

    @Test
    void cookieAndCsrf() throws Exception {
        FakeApi api = new FakeApi();
        Murkio client = api.client();
        Map<String, String> cookies = Map.of("__Host-murkio_session_" + HASH, api.token(), "__Host-murkio_uat_" + HASH, "1");
        assertNotNull(client.authenticate(request("GET", Map.of(), cookies), Options.of()).session());
        AuthResult blocked = client.authenticate(request("POST", Map.of("Sec-Fetch-Site", "cross-site"), cookies), Options.of());
        assertEquals("csrf", blocked.reason());
        assertTrue(blocked.signedInHint());
        assertNotNull(client.authenticate(request("POST", Map.of("Sec-Fetch-Site", "same-origin"), cookies), Options.of()).session());
        assertNotNull(client.authenticate(request("POST", Map.of("Origin", "https://app.example.com"), cookies), Options.of()).session());
        assertEquals("csrf", client.authenticate(request("POST", Map.of("Origin", "https://evil.example"), cookies), Options.of()).reason());
    }

    @Test
    void cookieNames() throws Exception {
        FakeApi api = new FakeApi();
        Murkio client = api.client();
        Map<String, String> plain = Map.of("murkio_session_" + HASH, api.token());
        assertEquals("missing", client.authenticate(request("GET", Map.of(), plain), Options.of()).reason());
        assertNotNull(client.authenticate(new Request("GET", "http", "localhost:8080", "/", Map.of(), plain), Options.of()).session());

        Map<String, String> secure = Map.of("__Secure-murkio_session_" + HASH, api.token());
        assertEquals("missing", client.authenticate(request("GET", Map.of(), secure), Options.of()).reason());
        Murkio shared = Murkio.builder().publishableKey(FakeApi.KEY).apiUrl("https://api.example.com").transport(api).cookieDomain(".example.com").build();
        assertNotNull(shared.authenticate(request("GET", Map.of(), secure), Options.of()).session());
    }

    @Test
    void expiredAndInvalid() throws Exception {
        FakeApi api = new FakeApi();
        Murkio client = api.client();
        String expired = api.token(Map.of("exp", 1), "k1");
        assertEquals("expired", client.authenticate(request("GET", Map.of("Authorization", "Bearer " + expired), Map.of()), Options.of()).reason());
        String other = api.token(Map.of("aud", "app-2"), "k1");
        assertEquals("invalid", client.authenticate(request("GET", Map.of("Authorization", "Bearer " + other), Map.of()), Options.of()).reason());
    }

    @Test
    void userAndRevocationAreCached() throws Exception {
        FakeApi api = new FakeApi();
        Murkio client = api.client();
        Map<String, String> headers = Map.of("Authorization", "Bearer " + api.token());
        Options options = Options.of().loadUser().checkRevocation();
        client.authenticate(request("GET", headers, Map.of()), options);
        AuthResult result = client.authenticate(request("GET", headers, Map.of()), options);
        assertEquals("ana@example.com", result.user().email());
        assertEquals(1, api.calls.stream().filter("POST /v1/me"::equals).count());
        assertEquals(1, api.calls.stream().filter("POST /v1/sessions/verify"::equals).count());

        String revoked = api.token(Map.of("jti", "revoked"), "k1");
        api.revoked.add(revoked);
        AuthResult refused = client.authenticate(request("GET", Map.of("Authorization", "Bearer " + revoked), Map.of()), Options.of().checkRevocation());
        assertNull(refused.session());
        assertEquals("revoked", refused.reason());
    }

    @Test
    void protect() throws Exception {
        FakeApi api = new FakeApi();
        Murkio client = api.client();
        assertEquals(401, client.protect(path("/api", Map.of(), Map.of()), Options.of().required()).response().status());

        Response redirect = client.protect(path("/dashboard?tab=1", PAGE, Map.of()), Options.of().required().signInUrl("/login")).response();
        assertEquals(302, redirect.status());
        assertEquals("/login?redirect=%2Fdashboard%3Ftab%3D1", redirect.headers().get("Location"));

        Map<String, String> headers = Map.of("Authorization", "Bearer " + api.token());
        assertEquals(403, client.protect(path("/admin", headers, Map.of()), Options.of().roles("admin")).response().status());
        assertNull(client.protect(path("/admin", headers, Map.of()), Options.of().roles("user")).response());
        Protected open = client.protect(path("/", Map.of(), Map.of()), Options.of());
        assertNull(open.response());
        assertFalse(open.result().signedIn());
    }

    @Test
    void handshake() throws Exception {
        Murkio client = new FakeApi().client();
        Map<String, String> hint = Map.of("__Host-murkio_uat_" + HASH, "1");
        Response page = client.protect(path("/dashboard", PAGE, hint), Options.of().required()).response();
        Matcher nonce = Pattern.compile("'nonce-([^']+)'").matcher(page.headers().get("Content-Security-Policy"));
        assertTrue(nonce.find());
        assertEquals(200, page.status());
        assertTrue(page.body().contains("nonce=\"" + nonce.group(1) + "\""));
        assertTrue(page.body().contains("data-murkio-key=\"" + FakeApi.KEY + "\""));
        assertTrue(page.headers().get("Content-Security-Policy").contains("connect-src https://api.example.com;"));
        assertTrue(page.headers().get("Set-Cookie").contains("murkio_handshake=1"));
        assertEquals("no-store", page.headers().get("Cache-Control"));

        Map<String, String> guarded = Map.of("__Host-murkio_uat_" + HASH, "1", "murkio_handshake", "1");
        assertEquals(401, client.protect(path("/dashboard", PAGE, guarded), Options.of().required()).response().status());
        assertEquals(401, client.protect(path("/dashboard", PAGE, hint), Options.of().required().noHandshake()).response().status());
    }

    @Test
    void pageHelpers() throws Exception {
        FakeApi api = new FakeApi();
        Murkio client = api.client();
        String head = client.head("/home");
        assertTrue(head.contains("integrity=\"" + Cdn.INTEGRITY + "\""), head);
        assertTrue(head.contains("crossorigin=\"anonymous\""));
        assertTrue(head.contains("data-murkio-after-login=\"/home\""));
        assertEquals("<murkio-identity-canvas></murkio-identity-canvas>", client.canvas());
        assertEquals("<murkio-identity-canvas class=\"&quot; onload=&quot;x\"></murkio-identity-canvas>", client.canvas(null, "\" onload=\"x"));
        assertEquals("<murkio-identity-email-input class=\"input\" placeholder=\"you@example.com\"></murkio-identity-email-input>", client.emailInput("input", "you@example.com"));
        assertEquals("<murkio-identity-login-button class=\"btn\" label=\"Entrar\"></murkio-identity-login-button>", client.loginButton("Entrar", "btn"));

        String inline = client.bootstrapScript();
        assertFalse(inline.contains("</script><b>"));
        assertTrue(inline.contains("data-generated-at="));
        String payload = inline.substring(inline.indexOf('>') + 1, inline.length() - "</script>".length());
        assertFalse(payload.contains("\u2028"));
        @SuppressWarnings("unchecked")
        Map<String, Object> canvas = (Map<String, Object>) Json.parseObject(payload).get("canvas");
        @SuppressWarnings("unchecked")
        Map<String, Object> document = (Map<String, Object>) canvas.get("document");
        assertEquals("</script><b>&\u2028", document.get("note"));

        Murkio selfHosted = Murkio.builder().publishableKey(FakeApi.KEY).transport(api).scriptUrl("https://static.example.com/murkio.js").build();
        assertFalse(selfHosted.head().contains("integrity"));
    }

    @Test
    void json() {
        Map<String, Object> value = Json.parseObject("{\"a\":[1,2.5,true,null,\"x\\n\\u00e9\"],\"b\":{\"c\":-3}}");
        assertEquals(List.of(1L, 2.5, true), ((List<?>) value.get("a")).subList(0, 3));
        assertEquals("x\n\u00e9", ((List<?>) value.get("a")).get(4));
        assertEquals("{\"k\":\"\\u003c/script\\u003e\\u0026\"}", Json.write(Map.of("k", "</script>&")));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":1} trailing"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":"));
        assertEquals(Map.of("a", "b"), Request.parseCookies("a=b; a=c; empty="));
    }
}
