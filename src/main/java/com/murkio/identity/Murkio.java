package com.murkio.identity;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Murkio for a Java backend: tells who is behind a request with only the
 * application's publishable key.
 *
 * <pre>{@code
 * Murkio murkio = Murkio.fromEnv();                 // MURKIO_PUBLISHABLE_KEY
 * Protected outcome = murkio.protect(request, Options.of().required().signInUrl("/login"));
 * }</pre>
 *
 * <p>{@code GET /v1/client} gives the application, the token issuer and the
 * JWKS, and the access tokens are verified locally (Ed25519, issuer, audience,
 * expiry), so a request costs no call to the API. The backend never signs
 * anyone in: the browser SDK does that, because the API rate-limits by the
 * user's IP. One instance is thread-safe and meant to be shared.
 */
public final class Murkio {
    public static final String DEFAULT_API_URL = "https://api.mukio.com";

    private static final long BOOTSTRAP_TTL = 60_000;
    private static final long USER_TTL = 60_000;
    private static final long REVOCATION_TTL = 30_000;
    private static final long JWKS_RETRY = 60_000;
    private static final int CACHE_LIMIT = 10_000;
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");
    private static final String HANDSHAKE_GUARD = "murkio_handshake";
    /** The DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw key follows. */
    private static final byte[] ED25519_SPKI_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String publishableKey;
    private final String apiUrl;
    private final String keyHash;
    private final String cookieDomain;
    private final String scriptUrl;
    private final String integrity;
    private final Transport transport;

    private final Object lock = new Object();
    private Map<String, Object> bootstrap;
    private long bootstrapAt;
    private Map<String, PublicKey> keys = Map.of();
    private long keysAt;
    private final Map<String, Cached<User>> users = new ConcurrentHashMap<>();
    private final Map<String, Cached<Boolean>> actives = new ConcurrentHashMap<>();

    private record Cached<T>(long at, T value) {
    }

    private Murkio(Builder builder) {
        String key = builder.publishableKey == null ? "" : builder.publishableKey;
        if (!key.startsWith("pk_")) {
            throw new IllegalArgumentException("murkio: set the publishable key (or MURKIO_PUBLISHABLE_KEY) to the application's publishable key (pk_...)");
        }
        this.publishableKey = key;
        String url = builder.apiUrl == null || builder.apiUrl.isBlank() ? DEFAULT_API_URL : builder.apiUrl;
        this.apiUrl = url.replaceAll("/+$", "");
        this.keyHash = fnv1a32(key);
        this.cookieDomain = builder.cookieDomain;
        this.scriptUrl = blankToNull(builder.scriptUrl);
        this.integrity = blankToNull(builder.integrity);
        this.transport = builder.transport != null ? builder.transport : defaultTransport(builder.timeout);
    }

    /** A client configured from MURKIO_PUBLISHABLE_KEY, MURKIO_API_URL, MURKIO_SCRIPT_URL and MURKIO_SCRIPT_INTEGRITY. */
    public static Murkio fromEnv() {
        return builder()
                .publishableKey(System.getenv("MURKIO_PUBLISHABLE_KEY"))
                .apiUrl(System.getenv("MURKIO_API_URL"))
                .scriptUrl(System.getenv("MURKIO_SCRIPT_URL"))
                .integrity(System.getenv("MURKIO_SCRIPT_INTEGRITY"))
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Configures a {@link Murkio}. Only the publishable key is required. */
    public static final class Builder {
        private String publishableKey;
        private String apiUrl;
        private String cookieDomain;
        private String scriptUrl;
        private String integrity;
        private Duration timeout = Duration.ofSeconds(10);
        private Transport transport;

        private Builder() {
        }

        public Builder publishableKey(String value) {
            this.publishableKey = value;
            return this;
        }

        public Builder apiUrl(String value) {
            this.apiUrl = value;
            return this;
        }

        /** The cookie domain set in the browser SDK, when the session cookie is shared with subdomains. */
        public Builder cookieDomain(String value) {
            this.cookieDomain = value;
            return this;
        }

        /** A self-hosted copy of the browser SDK (the same version) for head() and the handshake page. */
        public Builder scriptUrl(String value) {
            this.scriptUrl = value;
            return this;
        }

        public Builder integrity(String value) {
            this.integrity = value;
            return this;
        }

        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        public Builder transport(Transport value) {
            this.transport = value;
            return this;
        }

        public Murkio build() {
            return new Murkio(this);
        }
    }

    public String publishableKey() {
        return publishableKey;
    }

    public String apiUrl() {
        return apiUrl;
    }

    /** The hash that names the cookies of a publishable key (same as @murkio/html). */
    public static String fnv1a32(String value) {
        int hash = 0x811c9dc5;
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            hash ^= (b & 0xff);
            hash *= 0x01000193;
        }
        return String.format("%08x", hash);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    // --- API -----------------------------------------------------------------

    private static Transport defaultTransport(Duration timeout) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(timeout).build();
        return (method, url, headers, body) -> {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(timeout)
                    .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
            headers.forEach(request::header);
            HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
            return new Transport.Result(response.statusCode(), response.body());
        };
    }

    private Transport.Result send(String method, String url, Map<String, String> headers, String body) {
        try {
            return transport.send(method, url, headers, body);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new ApiException(0, "interrupted");
        } catch (RuntimeException runtime) {
            throw runtime;
        } catch (Exception error) {
            throw new ApiException(0, "unreachable");
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> call(String method, String path, Map<String, Object> body) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + publishableKey);
        headers.put("Accept", "application/json");
        String payload = null;
        if (body != null) {
            headers.put("Content-Type", "application/json");
            payload = Json.write(body);
        }
        Transport.Result result = send(method, apiUrl + path, headers, payload);
        Map<String, Object> decoded;
        try {
            decoded = Json.parseObject(result.body() == null ? "" : result.body());
        } catch (RuntimeException invalid) {
            decoded = Map.of();
        }
        if (result.status() < 200 || result.status() >= 300 || !(decoded.get("data") instanceof Map)) {
            String code = "http-" + result.status();
            if (decoded.get("details") instanceof List<?> details && !details.isEmpty() && details.get(0) instanceof Map<?, ?> first && first.get("code") != null) {
                code = String.valueOf(first.get("code"));
            }
            throw new ApiException(result.status(), code);
        }
        return (Map<String, Object>) decoded.get("data");
    }

    /** {@code GET /v1/client}: the application, its config and published canvas (cached a minute). */
    public Map<String, Object> bootstrap() {
        synchronized (lock) {
            if (bootstrap != null && System.currentTimeMillis() - bootstrapAt < BOOTSTRAP_TTL) {
                return bootstrap;
            }
        }
        Map<String, Object> fresh = call("GET", "/v1/client", null);
        synchronized (lock) {
            bootstrap = fresh;
            bootstrapAt = System.currentTimeMillis();
        }
        return fresh;
    }

    /**
     * The signing key of {@code kid}. The JWKS is fetched again only for an
     * unknown kid (a key rotation), at most once a minute.
     */
    private PublicKey publicKey(Map<String, Object> application, String kid) throws TokenException {
        synchronized (lock) {
            PublicKey known = keys.get(kid);
            if (known != null) {
                return known;
            }
            if (keysAt != 0 && System.currentTimeMillis() - keysAt < JWKS_RETRY) {
                throw new TokenException("unknown key", "invalid");
            }
            keysAt = System.currentTimeMillis();
        }

        String url = URI.create(apiUrl + "/").resolve(String.valueOf(application.get("jwks_url"))).toString();
        Transport.Result result = send("GET", url, Map.of("Accept", "application/json"), null);
        if (result.status() != 200) {
            throw new ApiException(result.status(), "http-" + result.status());
        }

        Map<String, PublicKey> fresh = new HashMap<>();
        if (Json.parseObject(result.body()).get("keys") instanceof List<?> list) {
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> jwk) || !"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv"))) {
                    continue;
                }
                try {
                    byte[] material = Base64.getUrlDecoder().decode(String.valueOf(jwk.get("x")));
                    if (material.length != 32) {
                        continue;
                    }
                    byte[] der = new byte[ED25519_SPKI_PREFIX.length + material.length];
                    System.arraycopy(ED25519_SPKI_PREFIX, 0, der, 0, ED25519_SPKI_PREFIX.length);
                    System.arraycopy(material, 0, der, ED25519_SPKI_PREFIX.length, material.length);
                    fresh.put(String.valueOf(jwk.get("kid")), KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der)));
                } catch (IllegalArgumentException | GeneralSecurityException skipped) {
                    // not a usable key: leave it out
                }
            }
        }
        synchronized (lock) {
            keys = fresh;
        }
        PublicKey key = fresh.get(kid);
        if (key == null) {
            throw new TokenException("unknown key", "invalid");
        }
        return key;
    }

    private static byte[] decodeSegment(String segment) throws TokenException {
        if (segment.isEmpty() || !segment.matches("[A-Za-z0-9_-]+")) {
            throw new TokenException("malformed token", "invalid");
        }
        try {
            return Base64.getUrlDecoder().decode(segment);
        } catch (IllegalArgumentException malformed) {
            throw new TokenException("malformed token", "invalid");
        }
    }

    private static Map<String, Object> jsonSegment(String segment) throws TokenException {
        try {
            return Json.parseObject(new String(decodeSegment(segment), StandardCharsets.UTF_8));
        } catch (RuntimeException malformed) {
            throw new TokenException("malformed token", "invalid");
        }
    }

    /**
     * Verifies an access token locally: an EdDSA signature by one of the
     * application's keys, the issuer, the audience (the application) and the
     * expiry.
     *
     * @throws TokenException with reason {@code expired} or {@code invalid}
     */
    public Session verify(String token) throws TokenException {
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3) {
            throw new TokenException("malformed token", "invalid");
        }
        Map<String, Object> header = jsonSegment(parts[0]);
        if (!"EdDSA".equals(header.get("alg"))) {
            throw new TokenException("unsupported algorithm", "invalid");
        }

        Map<String, Object> application = bootstrap();
        PublicKey key = publicKey(application, String.valueOf(header.get("kid")));
        boolean valid;
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            valid = verifier.verify(decodeSegment(parts[2]));
        } catch (GeneralSecurityException invalid) {
            valid = false;
        }
        if (!valid) {
            throw new TokenException("invalid signature", "invalid");
        }

        Map<String, Object> claims = jsonSegment(parts[1]);
        Object subject = claims.get("sub");
        Object sessionId = claims.get("sid");
        Object expires = claims.get("exp");
        if (!String.valueOf(application.get("issuer")).equals(claims.get("iss"))
                || !String.valueOf(application.get("application_id")).equals(claims.get("aud"))
                || !(subject instanceof String sub) || sub.isEmpty()
                || !(sessionId instanceof String sid) || sid.isEmpty()
                || !(expires instanceof Number exp)) {
            throw new TokenException("invalid claims", "invalid");
        }
        if (System.currentTimeMillis() / 1000.0 >= exp.doubleValue()) {
            throw new TokenException("expired token", "expired");
        }

        List<String> roles = new ArrayList<>();
        if (claims.get("roles") instanceof List<?> list) {
            list.forEach(role -> roles.add(String.valueOf(role)));
        }
        return new Session(sub, sid, String.valueOf(application.get("application_id")), List.copyOf(roles), claims, token);
    }

    /** The profile of the session's user ({@code POST /v1/me}), cached a minute per session. */
    public User user(Session session) {
        Cached<User> hit = users.get(session.sessionId());
        if (hit != null && System.currentTimeMillis() - hit.at() < USER_TTL) {
            return hit.value();
        }
        Map<String, Object> data = call("POST", "/v1/me", Map.of("access_token", session.token()));
        List<String> roles = new ArrayList<>();
        if (data.get("roles") instanceof List<?> list) {
            list.forEach(role -> roles.add(String.valueOf(role)));
        }
        User user = new User(
                String.valueOf(data.get("id")), String.valueOf(data.get("session_id")),
                data.get("email") == null ? null : String.valueOf(data.get("email")),
                Boolean.TRUE.equals(data.get("email_verified")), List.copyOf(roles),
                Boolean.TRUE.equals(data.get("mfa_enabled")), String.valueOf(data.get("created_at")));
        if (users.size() >= CACHE_LIMIT) {
            users.clear();
        }
        users.put(session.sessionId(), new Cached<>(System.currentTimeMillis(), user));
        return user;
    }

    /** False when the API says the session was revoked (logout, ban). Cached 30 s. */
    public boolean isActive(Session session) {
        Object jti = session.claims().get("jti");
        String key = jti == null ? session.token() : String.valueOf(jti);
        Cached<Boolean> hit = actives.get(key);
        if (hit != null && System.currentTimeMillis() - hit.at() < REVOCATION_TTL) {
            return hit.value();
        }
        boolean active = Boolean.TRUE.equals(call("POST", "/v1/sessions/verify", Map.of("access_token", session.token())).get("active"));
        if (actives.size() >= CACHE_LIMIT) {
            actives.clear();
        }
        actives.put(key, new Cached<>(System.currentTimeMillis(), active));
        return active;
    }

    // --- requests ------------------------------------------------------------

    private List<String[]> cookieNames(String host) {
        List<String[]> names = new ArrayList<>();
        names.add(new String[] {"__Host-murkio_session_" + keyHash, "__Host-murkio_uat_" + keyHash});
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            names.add(new String[] {"__Secure-murkio_session_" + keyHash, "__Secure-murkio_uat_" + keyHash});
        }
        String hostname = host.startsWith("[") ? host.substring(1, Math.max(1, host.indexOf(']'))) : host.replaceAll(":\\d+$", "");
        if (hostname.equals("localhost") || hostname.equals("127.0.0.1") || hostname.equals("::1")) {
            names.add(new String[] {"murkio_session_" + keyHash, "murkio_uat_" + keyHash});
        }
        return names;
    }

    private static boolean sameOrigin(Request request) {
        String site = request.header("sec-fetch-site");
        if (!site.isEmpty()) {
            return site.equals("same-origin");
        }
        String origin = request.header("origin");
        return !origin.isEmpty() && origin.equals(request.scheme() + "://" + request.host());
    }

    /**
     * Finds and verifies the session of a request.
     *
     * <p>The token comes from {@code Authorization: Bearer} or from the session
     * cookie the browser SDK writes. The cookie goes with every request to the
     * site, including ones another site makes the browser send, so it only
     * counts for GET, HEAD and OPTIONS or for same-origin requests.
     */
    public AuthResult authenticate(Request request, Options options) {
        List<String[]> names = cookieNames(request.host());
        boolean hint = names.stream().anyMatch(name -> "1".equals(request.cookies().get(name[1])));

        String token = "";
        String authorization = request.header("authorization");
        if (authorization.startsWith("Bearer ")) {
            String value = authorization.substring(7).trim();
            if (!value.startsWith("pk_") && !value.startsWith("sk_")) {
                token = value;
            }
        }
        if (token.isEmpty()) {
            for (String[] name : names) {
                String value = request.cookies().get(name[0]);
                if (value != null && !value.isEmpty()) {
                    token = value;
                    break;
                }
            }
            if (token.isEmpty()) {
                return new AuthResult(null, null, "missing", hint);
            }
            if (!SAFE_METHODS.contains(request.method().toUpperCase(Locale.ROOT)) && !sameOrigin(request)) {
                return new AuthResult(null, null, "csrf", hint);
            }
        }

        Session session;
        try {
            session = verify(token);
        } catch (TokenException refused) {
            return new AuthResult(null, null, refused.reason(), hint);
        }

        if (options.checkRevocation) {
            boolean active;
            try {
                active = isActive(session);
            } catch (ApiException unreachable) {
                active = false;
            }
            if (!active) {
                return new AuthResult(null, null, "revoked", hint);
            }
        }
        User user = null;
        if (options.loadUser) {
            try {
                user = user(session);
            } catch (ApiException unreachable) {
                user = null;
            }
        }
        return new AuthResult(session, user, null, hint);
    }

    /**
     * Authenticates a request and decides what to answer: the response is the
     * 401, 403, redirect to the sign-in URL or the handshake page that
     * refreshes an expired session cookie, or null to run the route.
     */
    public Protected protect(Request request, Options options) {
        AuthResult result = authenticate(request, options);
        if (result.session() != null) {
            if (!options.roles.isEmpty() && !result.session().hasRole(options.roles.toArray(String[]::new))) {
                return new Protected(result, json(403, "forbidden"));
            }
            return new Protected(result, null);
        }

        boolean navigation = request.method().equalsIgnoreCase("GET")
                && (request.header("sec-fetch-mode").equals("navigate") || request.header("accept").contains("text/html"));
        String guard = request.cookies().get(HANDSHAKE_GUARD);
        if (options.handshake && navigation && result.signedInHint()
                && ("missing".equals(result.reason()) || "expired".equals(result.reason()))
                && (guard == null || guard.isEmpty())) {
            return new Protected(result, handshake(request.scheme()));
        }

        if (!options.required && options.roles.isEmpty()) {
            return new Protected(result, null);
        }
        if (navigation && !options.signInUrl.isEmpty()) {
            String separator = options.signInUrl.contains("?") ? "&" : "?";
            String location = options.signInUrl + separator + "redirect=" + URLEncoder.encode(request.path(), StandardCharsets.UTF_8);
            return new Protected(result, new Response(302, Map.of("Location", location, "Cache-Control", "no-store"), ""));
        }
        return new Protected(result, json(401, "unauthorized"));
    }

    private static Response json(int status, String message) {
        return new Response(status, Map.of("Content-Type", "application/json", "Cache-Control", "no-store"), Json.write(Map.of("error", message)));
    }

    private static String origin(String url, String fallback) {
        try {
            URI uri = URI.create(url);
            if (uri.getHost() == null) {
                return fallback;
            }
            return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "");
        } catch (IllegalArgumentException invalid) {
            return fallback;
        }
    }

    private Response handshake(String scheme) {
        byte[] raw = new byte[16];
        RANDOM.nextBytes(raw);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String scriptOrigin = origin(scriptUrl != null ? scriptUrl : Cdn.URL, "https://cdn.jsdelivr.net");
        String page = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex\"><title></title>\n"
                + scriptTag(nonce, null, null, null) + "\n"
                + "<script nonce=\"" + nonce + "\">(async function(){try{var m=window.Murkio&&window.Murkio.getMurkio();"
                + "if(m)await m.getToken();}catch(e){}location.replace(location.href);})();</script>\n"
                + "</head><body></body></html>";
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "text/html; charset=utf-8");
        headers.put("Cache-Control", "no-store");
        headers.put("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + nonce + "' " + scriptOrigin
                + "; connect-src " + origin(apiUrl, apiUrl) + "; base-uri 'none'; frame-ancestors 'none'");
        headers.put("Set-Cookie", HANDSHAKE_GUARD + "=1; Path=/; Max-Age=30; SameSite=Lax" + ("https".equals(scheme) ? "; Secure" : ""));
        return new Response(200, headers, page);
    }

    // --- pages ---------------------------------------------------------------

    static String escape(String value) {
        return value.replace("&", "&amp;").replace("\"", "&quot;").replace("'", "&#39;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String attributes(String... pairs) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            if (pairs[i + 1] != null && !pairs[i + 1].isEmpty()) {
                output.append(' ').append(pairs[i]).append("=\"").append(escape(pairs[i + 1])).append('"');
            }
        }
        return output.toString();
    }

    private String scriptTag(String nonce, String afterLogin, String locale, String oauthRedirectUrl) {
        String pinned = scriptUrl != null ? integrity : Cdn.INTEGRITY;
        return "<script" + attributes(
                "src", scriptUrl != null ? scriptUrl : Cdn.URL,
                "integrity", pinned,
                "crossorigin", pinned != null ? "anonymous" : null,
                "nonce", nonce,
                "data-murkio-key", publishableKey,
                "data-murkio-api", apiUrl,
                "data-murkio-locale", locale,
                "data-murkio-after-login", afterLogin,
                "data-murkio-oauth-redirect", oauthRedirectUrl) + "></script>";
    }

    /** The {@code <script>} that loads the browser SDK, pinned with its SRI hash. Put it in {@code <head>}. */
    public String head() {
        return scriptTag(null, null, null, null);
    }

    /** {@link #head()} with the page to open after signing in. */
    public String head(String afterLogin) {
        return scriptTag(null, afterLogin, null, null);
    }

    /** {@link #head()} with every option (any may be null). */
    public String head(String afterLogin, String locale, String oauthRedirectUrl, String nonce) {
        return scriptTag(nonce, afterLogin, locale, oauthRedirectUrl);
    }

    /**
     * Inlines {@code GET /v1/client} so the browser draws the canvas without
     * fetching it. The JSON writer escapes {@code <}, {@code >}, {@code &} and
     * the U+2028/U+2029 separators, so it cannot end the {@code <script>} tag.
     */
    public String bootstrapScript() {
        return "<script type=\"application/json\" id=\"murkio-bootstrap\" data-generated-at=\"" + System.currentTimeMillis() + "\">"
                + Json.write(bootstrap()) + "</script>";
    }

    /** {@code <murkio-identity-canvas>}: the login canvas designed in the dashboard. */
    public String canvas() {
        return canvas(null, null);
    }

    public String canvas(String screen, String cssClass) {
        return "<murkio-identity-canvas" + attributes("screen", screen, "class", cssClass) + "></murkio-identity-canvas>";
    }

    private static String field(String tag, String cssClass, String placeholder, String label) {
        return "<" + tag + attributes("class", cssClass, "placeholder", placeholder, "label", label) + "></" + tag + ">";
    }

    public String emailInput(String cssClass, String placeholder) {
        return field("murkio-identity-email-input", cssClass, placeholder, null);
    }

    public String passwordInput(String cssClass, String placeholder) {
        return field("murkio-identity-password-input", cssClass, placeholder, null);
    }

    public String keepLogged(String label, String cssClass) {
        return field("murkio-identity-keep-logged", cssClass, null, label);
    }

    public String loginButton(String label, String cssClass) {
        return field("murkio-identity-login-button", cssClass, null, label);
    }

    public String registerButton(String label, String cssClass) {
        return field("murkio-identity-register-button", cssClass, null, label);
    }

    public String errorMessage(String cssClass) {
        return field("murkio-identity-error", cssClass, null, null);
    }
}
