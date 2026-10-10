# Murkio identity for Java

Tells who is behind each request and writes the login components into the pages you
render. Java 17+, no dependencies (the servlet filter needs Jakarta Servlet, which your
container already provides). The only setting is your publishable key.

```xml
<dependency>
  <groupId>com.murkio</groupId>
  <artifactId>murkio-identity</artifactId>
  <version>0.1.0</version>
</dependency>
```

```sh
MURKIO_PUBLISHABLE_KEY=pk_...    # MURKIO_API_URL is optional
```

## Spring Boot 3

```java
@Configuration
class MurkioConfig {
    @Bean
    Murkio murkio() {
        return Murkio.fromEnv();
    }

    @Bean
    FilterRegistrationBean<MurkioFilter> murkioFilter(Murkio murkio) {
        var bean = new FilterRegistrationBean<>(new MurkioFilter(murkio, Options.of().required().signInUrl("/login").loadUser()));
        bean.addUrlPatterns("/dashboard/*", "/api/*");
        return bean;
    }
}

@GetMapping("/dashboard")
String dashboard(HttpServletRequest request) {
    AuthResult auth = MurkioFilter.get(request);        // .session(), .user()
    return "Hello " + auth.user().email();
}

@GetMapping(value = "/login", produces = "text/html")
String login() {
    return "<head>" + murkio.head("/dashboard") + murkio.bootstrapScript() + "</head><body>" + murkio.canvas() + "</body>";
}
```

With Thymeleaf print the helpers unescaped: `<th:block th:utext="${murkio.canvas()}"/>`.
They are already escaped.

## Any other server

```java
Request request = new Request(method, scheme, host, pathWithQuery, headers, Request.parseCookies(cookieHeader));
Protected outcome = murkio.protect(request, Options.of().required().roles("admin"));
if (outcome.response() != null) {
    // send outcome.response().status(), .headers() and .body() and stop
}
Session session = outcome.result().session();
```

## Your own layout

```java
murkio.emailInput("input", "you@example.com");
murkio.passwordInput("input", null);
murkio.keepLogged("Keep me signed in", null);
murkio.loginButton("Sign in", "btn");
murkio.registerButton("Create account", "btn");
murkio.errorMessage(null);
```

## How it works

The same contract as the other server SDKs (`libs/spec/server`): `GET /v1/client` gives
the application, issuer and JWKS; access tokens are verified locally (Ed25519 from the
JDK, `iss`, `aud`, `exp`); the token comes from `Authorization: Bearer` or the `__Host-`
session cookie of the browser SDK, which only counts for GET/HEAD/OPTIONS or same-origin
requests (CSRF). `loadUser()` reads `POST /v1/me` (cached a minute); `checkRevocation()`
asks the API whether the session was revoked (cached 30 s). A page request with an
expired cookie gets a short handshake page that refreshes it. The backend never signs
anyone in: the browser does. One `Murkio` is thread-safe; share it.
