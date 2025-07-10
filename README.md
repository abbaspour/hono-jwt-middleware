# Hono JWT Middleware

An authorization middleware for [Hono](https://hono.dev) web framework. Built on top of the amazing [jose](https://github.com/panva/jose) library, this package provides a simple way to secure your Hono API using JWT tokens.

This library adds two features on top of jose:

1. issuerResolver that allows defining a dynamic list of issuers
2. DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) support
