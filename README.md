# jwt-inspector - inspect your JWTs

jwt-inspector is an service that consumes JWT bearer tokens, validates them using a provided JWKS URI, and echoes the JWT payload in the response.

# Getting started

jwt-inspector is a Go service. To install it, use `go build` or run:

```
go install github.com/jnschaeffer/jwt-inspector@latest
```

# Usage

To run jwt-inspector, set the `JWKS_URI` environment variable to the URI containing the JWKS you want to validate tokens against and run the binary:

```
JWKS_URI=https://example.com/.well-known/jwks.json jwt-inspector
```

You can also set the listening address for the service using the `ADDR` environment variable.

Once running, jwt-inspector will accept requests on `/` and echo JWT payloads.

The following example should give you an idea of how to use the service:

```
$ read -s AUTH_TOKEN
$ curl -s --oauth2-bearer "$AUTH_TOKEN" http://localhost:8000/ | jq
{
  "aud": "https://auth.example.com/",
  "exp": 1674233937,
  "iat": 1674147537,
  "iss": "https://auth.example.com/",
  "scope": "openid profile email",
  "sub": "0e5ed04b-d67f-4559-9ee6-46567cfd16da"
}
```
