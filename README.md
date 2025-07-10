# Hono JWT Middleware

An authorization middleware for [Hono](https://hono.dev) web framework. Built on top of the amazing [jose](https://github.com/panva/jose) library, this package provides a simple way to secure your Hono API using JWT tokens.

This library adds two features on top of jose's jwtVerify():

1. [IssuerResolver](./src/index.ts) that allows defining a dynamic list of issuers
2. DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) support

## Installation

```bash
npm install github:abbaspour/hono-jwt-middleware
```

## Basic Usage

```ts
import {Context, Hono} from 'hono';
import {IssuerResolver, jwt, requireScope} from 'hono-jwt-middleware';
import {type JWTHeaderParameters, JWTPayload} from 'jose';

interface Env {
  Bindings: {
    AUDIENCE: string;
    DPoP: boolean;
  };
  Variables: {
    user: JWTPayload;
    jwtHeader: JWTHeaderParameters;
  };
}

const issuerResolver: IssuerResolver = async (issuer: string, ctx: Context): Promise<string> => {
  const requestDomain = new URL(ctx.req.url).host;
  const domainInfo = await memoizedExistsInDB(requestDomain, ctx.env.DB);
  if (!domainInfo) {
    throw new Error(`no registered configuration found for domain ${requestDomain}.`);
  }
  return domainInfo.jwks_uri || `${issuer}.well-known/jwks.json`;
};

const app = new Hono<Env>();

app.use('/api/*', (c, next) => {
  const audience = c.env.AUDIENCE;
  if (!audience) throw new Error('AUDIENCE env variable is not set');
  const jwtMiddleware = jwt({
    issuerResolver,
    dpop: c.env.DPoP || false,
    audience,
  });
  return jwtMiddleware(c, next);
});

app.get('/api/applications/:id', requireScope('read'), (c) => {
    const id = c.req.param('id');
    const application = getJobApplicationById(id);

    if (!application) {
        return c.json({error: 'Application not found'}, 404);
    }

    return c.json(application);
});

export default app;
```
