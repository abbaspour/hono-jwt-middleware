import type {Context} from 'hono';
import type {MiddlewareHandler} from 'hono/types';
import * as jose from 'jose';
import {HTTPException} from 'hono/http-exception';

export type IssuerResolver = (issuer: string, ctx: Context) => Promise<string | URL | jose.CryptoKey | Uint8Array<ArrayBufferLike>>;

// Base options with dpop but without issuer or issuerResolver
export type BaseJWTOptions = Omit<jose.JWTVerifyOptions, 'issuer'> & {
  dpop?: boolean;
};

// Options with issuer
export type IssuerOptions = BaseJWTOptions & {
  issuer: string | string[];
  issuerResolver?: never;
};

// Options with issuerResolver
export type IssuerResolverOptions = BaseJWTOptions & {
  issuer?: never;
  issuerResolver: IssuerResolver;
};

// Union type that enforces either issuer or issuerResolver, but not both
export type ExtendedJWTVerifyOptions = IssuerOptions | IssuerResolverOptions;

// Extended JWT payload interface to include cnf (confirmation) claim
interface ExtendedJWTPayload extends jose.JWTPayload {
  cnf?: {
    jkt?: string;
    [key: string]: unknown;
  };
}

// from jose
function isCloudflareWorkers() {
  return (
    // @ts-ignore
    typeof WebSocketPair !== 'undefined' ||
    (typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers') ||
    // @ts-expect-error EdgeRuntime is not defined outside vercel
    (typeof EdgeRuntime !== 'undefined' && EdgeRuntime === 'vercel')
  );
}

const jwksCache: jose.JWKSCacheInput = {};

// @ts-expect-error caches.default injected by cloudflare
const cache = caches.default;

const decoder = new TextDecoder();

async function fetchWithCloudflareCache(ctx: Context, request: string, init?: RequestInit): Promise<Response> {
  const cacheUrl = new URL(request);

  // Construct the cache key from the cache URL
  const cacheKey = new Request(cacheUrl.toString(), init);

  // Check whether the value is already available in the cache
  // if not, you will need to fetch it from origin, and store it in the cache
  let response = await cache.match(cacheKey);

  if (!response) {
    console.log(`Response for request url: ${request} not present in cache. Fetching and caching request.`);
    // If not in cache, get it from origin
    response = await fetch(request, init);

    // Must use Response constructor to inherit all of response's fields
    response = new Response(response.body, response);

    // Cache API respects Cache-Control headers. Setting s-max-age to 10
    // will limit the response to be in cache for 10 seconds max

    // Any changes made to the response here will be reflected in the cached value
    response.headers.append('Cache-Control', 's-maxage=10'); // Note: how long to cache in Cloudflare cache

    ctx.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  } else {
    console.log(`Cache hit for: ${request}.`);
  }
  return response;
}

function buildGetKeyAndValidateIssuer(issuerResolver: IssuerResolver, ctx: Context): jose.JWTVerifyGetKey {
  return async function getKeyAndValidateIssuer(
    header: jose.JWSHeaderParameters,
    jws: jose.FlattenedJWSInput,
  ): Promise<jose.CryptoKey | Uint8Array<ArrayBufferLike>> {
    let iss: string;
    try {
      ({iss} = JSON.parse(decoder.decode(jose.base64url.decode(jws.payload))));
    } catch (cause) {
      throw new Error('failed to decode payload: ' + cause);
    }

    if (!iss) {
      throw new Error('JWT is missing the "iss" (issuer) claim');
    }

    const key = await issuerResolver(iss, ctx);

    if (!key) {
      throw new Error(`invalid issuer: ${iss}`);
    }

    if (typeof key === 'string' || key instanceof URL) {
      const jwksUrl: URL = typeof key === 'string' ? new URL(key) : key;

      return jose.createRemoteJWKSet(jwksUrl, {
        [jose.customFetch]: (url: string, options) =>
          isCloudflareWorkers() ? fetchWithCloudflareCache(ctx, url, options) : fetch(url, options),
        [jose.jwksCache]: jwksCache, // note: this is required, otherwise it will try to fetch everytime.
      })!(header, jws);
    } else {
      return key;
    }
  };
}

// noinspection JSUnusedGlobalSymbols
export const jwt = (options?: ExtendedJWTVerifyOptions): MiddlewareHandler => {
  let staticJWKS: ReturnType<typeof jose.createRemoteJWKSet> | null = null;

  const issuerResolver =
    typeof options?.issuerResolver === 'function' ? (options?.issuerResolver as IssuerResolver) : undefined;

  return async function jwt(ctx, next) {
    console.log('running jwt middleware');

    // step 2 - fetch token from header
    const token = getToken(ctx, options?.dpop || false);

    // step 3 - find suitable access_token validation key
    let JWKS;

    if (issuerResolver) {
      JWKS = buildGetKeyAndValidateIssuer(issuerResolver, ctx);
    } else {
      if (staticJWKS) {
        JWKS = staticJWKS;
      } else {
        if (options?.issuer) {
          staticJWKS = jose.createRemoteJWKSet(new URL(`${options.issuer}.well-known/jwks.json`));
        } else {
          throw new Error('Either issuerResolver or issuer must be provided');
        }
      }
      JWKS = staticJWKS;
    }

    // step 4 - validate access_token
    let accessTokenPayload: ExtendedJWTPayload | null = null;
    let accessTokenProtectedHeader: jose.JWTHeaderParameters | null = null;

    try {
      const verified = await jose.jwtVerify(token, JWKS, options);

      accessTokenPayload = verified.payload;
      accessTokenProtectedHeader = verified.protectedHeader;
    } catch (e) {
      console.log('validation exception', e);
      throw new HTTPException(401, {
        message: 'Unauthorized',
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_token',
          statusText: 'Unauthorized',
          errDescription: 'Token verification failure',
        }),
        cause: e,
      });
    }

    // step 5 - validate dpop if enabled
    if (options?.dpop && !(await validDPoP(ctx, accessTokenPayload!))) {
      console.log('DPoP validation failed');
      throw new HTTPException(401, {
        message: 'Unauthorized',
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_token',
          statusText: 'Unauthorized',
          errDescription: 'DPoP verification failure',
        }),
      });
    }

    // step 6 - attach token to ctx.user
    ctx.set('user', accessTokenPayload);
    ctx.set('jwtHeader', accessTokenProtectedHeader);

    await next();
  };
};

async function validDPoP(ctx: Context, accessTokenPayload: ExtendedJWTPayload): Promise<boolean> {
  // Extract DPoP header
  const dpopHeader = ctx.req.raw.headers.get('DPoP');

  if (!dpopHeader) {
    return false;
  }

  // Validate DPoP proof for the current resource
  try {
    const {payload, protectedHeader} = await jose.jwtVerify(dpopHeader, jose.EmbeddedJWK, {});

    //console.log(`DPoP payload: ${JSON.stringify(payload)}, header: ${JSON.stringify(protectedHeader)}`);

    if (payload?.htm !== ctx.req.method || payload?.htu !== ctx.req.url) {
      return false; // 'DPoP htm/htu not matched'
    }

    const calculatedThumbprint = await jose.calculateJwkThumbprint(protectedHeader.jwk as jose.JWK);

    // Compare the token's cnf.jkt claim with the calculated thumbprint
    if (accessTokenPayload?.cnf?.jkt !== calculatedThumbprint) {
      return false; // 'DPoP proof JWK thumbprint does not match the token cnf.jkt claim';
    }

    // DPoP validation successful
    console.log('DPoP validation successful');
    return true;
  } catch (dpopError) {
    console.log(`dpopError during validation: ${dpopError}`);
    return false;
  }
}

function getToken(ctx: Context, dpop: boolean): string {
  const credentials = ctx.req.raw.headers.get('Authorization');

  if (!credentials) {
    const errDescription = 'No Authorization header included in request';
    throw new HTTPException(401, {
      message: errDescription,
      res: unauthorizedResponse({
        ctx,
        error: 'invalid_request',
        errDescription,
      }),
    });
  }

  const parts = credentials.split(/\s+/);
  if (parts.length !== 2) {
    const errDescription = 'Invalid Authorization header structure';
    throw new HTTPException(401, {
      message: errDescription,
      res: unauthorizedResponse({
        ctx,
        error: 'invalid_request',
        errDescription,
      }),
    });
  }

  const token_type = dpop ? 'DPoP' : 'Bearer';

  if (parts[0] !== token_type) {
    const errDescription = `Invalid authorization header (only ${token_type} tokens are supported)`;
    throw new HTTPException(401, {
      message: errDescription,
      res: unauthorizedResponse({
        ctx,
        error: 'invalid_request',
        errDescription,
      }),
    });
  }

  const token = parts[1];
  if (!token || token.length === 0) {
    const errDescription = 'No token included in request';
    throw new HTTPException(401, {
      message: errDescription,
      res: unauthorizedResponse({
        ctx,
        error: 'invalid_request',
        errDescription,
      }),
    });
  }

  return token;
}

function unauthorizedResponse(opts: {ctx: Context; error: string; errDescription: string; statusText?: string}) {
  return new Response('Unauthorized', {
    status: 401,
    statusText: opts.statusText,
    headers: {
      'WWW-Authenticate': `Bearer realm="${opts.ctx.req.url}",error="${opts.error}",error_description="${opts.errDescription}"`,
    },
  });
}

// noinspection JSUnusedGlobalSymbols
export function requireScope(scope: string): MiddlewareHandler {
  return async function requireScope(ctx, next) {
    console.log(`running requireScope middleware for scope: ${scope}`);
    const payload = ctx.var.user as jose.JWTPayload;
    if (!payload?.scope) {
      throw new HTTPException(403, {
        message: 'Forbidden',
        res: unauthorizedResponse({
          ctx,
          error: 'insufficient_scope',
          errDescription: `Missing required scope: ${scope}`,
        }),
      });
    }

    const scopes = Array.isArray(payload.scope) ? payload.scope : (payload.scope as string).split(' ');
    if (!scopes || !scopes.includes(scope)) {
      throw new HTTPException(403, {
        message: 'Forbidden',
        res: unauthorizedResponse({
          ctx,
          error: 'insufficient_scope',
          errDescription: `Missing required scope: ${scope}`,
        }),
      });
    }

    await next();
  };
}
