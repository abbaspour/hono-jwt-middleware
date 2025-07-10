import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { jwt, requireScope } from '../src/index';
import * as jose from 'jose';
import {type JWTHeaderParameters, JWTPayload} from 'jose';

interface Env {
  Variables: {
    user: JWTPayload;
    jwtHeader: JWTHeaderParameters;
  };
}

// Test utilities
const createMockContext = (headers: Record<string, string> = {}) => {
  const req = new Request('https://example.com', {
    headers: new Headers(headers),
  });
  const app = new Hono<Env>();
  return app.handle(req);
};

// Hard-coded keys for RS256 testing
const RS256_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
agU/GCosBKS9ruSkVH0Wc4lnX8W1GTr1dsdmtMofPeLE3KIgHjueHwUlV1+HMqvi
qB8rdZFsWS6hd2fLOO0Wd/t9QjrQk/KsB9KTcw8GZdNKlYUoTUVPIf+RXQYiP/Io
E3jdU6QsQWZPqKywGMG6GDuLK6k99d97/TK0OVtE0hDJvkn3D1iqK+22e5K/YYM5
b0+9AgMBAAECggEAVc6bu7VAnP6v0gDOeX4razv4FX/adCqwv8A0QH6tm2OmmWrL
5R9+c7Xr1/kJwLn+5p3qasyfQpnmVjUE9nGXj1DRATJ0IN3PjzKL8hR3PQYJpZuF
z7GWjmPHHqLjvd3I7nnkKQ6dwP0Kn4vWwxkXzjyLpvIIEgxLzrObjqVwkZyTwI1y
Xr5JIAzAzwMFBwNszsDVFbK6JD5fs4ZGdSYVQQl9+ZMYnFdqFXDTqhkj5+nKpLYt
hmYEaPMyLfQj62KQNIT1J/wVN00jZGDngrcRtWNGl/tQXQnWg7zKFvIvz9dGCcj0
PHvN9yMk7E8fqZpeI8EFoetoFbvfWEOuZuqU6M+rAQKBgQDfLNcnS0LzpsS2aK8R
qDCvDVysATg1NLuiNMNTZDTttVTuZD2FXjgS/u5QGEXYJpMl8eQJqIWwzlMYQbRM
8zYvDFBHuofQkRUb2GNe2W2tQR+68ZRIzrY/K0bS8P+rBK5V+Rt5kb5tgXQoZIj5
RKz1lWHJ9fKnrOaFXzPVtC9RXQKBgQDXAiSdY7Yrkl5qTY/Ug3zER4TMbw6+Pdor
Ks3c313JU8Ufad/SzIBQUUkD6s8FXAOPCvx9aQjh10X9TlQFXn1wGS/RfJK3ScpX
CTR8+8HR6Nt40Mn5RIjLKVv8n/K5jKn3tU1XnqjFDwfYx2aZGUTJRs5vc2e9xUlV
tP5Q04AdIQKBgQC+9/lZ8telbpqMqpqwqRaJ8LMn5JYO3ZLynZbKxKbJ7MgCY8pD
TPUUKpvf/LVN8YhU0uIVNYVHWFTbwj5oqEMC8CtmREPAoaOXnYvSD3HqNQKBUWvz
tqLFJUDnDZuqsGY2i/rDzPu4UvPpOA7nMj5Vro0sBzksaZaPtZifBs9UhQKBgDQ1
0O5SRmtU4QDrPT0FDmLdKQhvS+zLsKV/K5N2Uv+8RxLQ7hCOQNGvdvT9pV1UkGpC
HG9A46ydGQZfzMPkK8AAUPmTjDQNmVUxKQHHzWLDbrO36MkQJl7PRHGf39EuEHBz
Kk4fUaLoWoX0xYhLKBFNgzBZEwP5Pjki/24lY8+hAoGAW24WXNm3i3JGMzpxZbYo
0YUmVVIrDyBQYl7hBJcYnK3A8j4dOQMe1TvQ0xpW6JQyzxj3Z2OXz3GLiEXe0YeB
lXSTJjQfG4vnGXlhv5YX6XKzH3rDc5FCj0tHYrGCQWkgbHrGAKXGGMmL5bP5y1J0
zO/wIx3fLlu0a+0NtsbADA0=
-----END PRIVATE KEY-----`;

const RS256_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWWoFPxgq
LASkva7kpFR9FnOJZ1/FtRk69XbHZrTKHz3ixNyiIB47nh8FJVdfhzKr4qgfK3WR
bFkuoXdnyzjtFnf7fUI60JPyrAfSk3MPBmXTSpWFKE1FTyH/kV0GIj/yKBN43VOk
LEFmT6issBjBuhg7iyupPfXfe/0ytDlbRNIQyb5J9w9YqivttnuSv2GDOW9PvQID
AQAB
-----END PUBLIC KEY-----`;

describe('JWT Middleware', () => {
  // Test for HS256 tokens
  describe('HS256 Tokens', () => {
    const secret = new TextEncoder().encode('test-secret');
    let validToken: string;

    beforeEach(async () => {
      // Create a valid HS256 token
      validToken = await new jose.SignJWT({ sub: 'test-user', scope: 'read:data' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('https://test-issuer.example.com/')
        .setExpirationTime('1h')
        .sign(secret);
    });

    it('should validate a valid HS256 token with string issuer', async () => {
      const app = new Hono<Env>();
      let userPayload: JWTPayload | null = null;

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'https://test-issuer.example.com/') {
          return secret;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.get('/protected', (c) => {
        userPayload = c.get('user');
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${validToken}`
        }
      }));

      expect(res.status).toBe(200);
      expect(userPayload).not.toBeNull();
      expect(userPayload.sub).toBe('test-user');
      expect(userPayload.iss).toBe('https://test-issuer.example.com/');
    });

    it('should validate a valid HS256 token with array of issuers', async () => {
      const app = new Hono<Env>();
      let userPayload: any = null;

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'https://test-issuer.example.com/' || issuer === 'https://other-issuer.example.com/') {
          return secret;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.get('/protected', (c) => {
        userPayload = c.get('user');
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${validToken}`
        }
      }));

      expect(res.status).toBe(200);
      expect(userPayload).not.toBeNull();
      expect(userPayload.sub).toBe('test-user');
      expect(userPayload.iss).toBe('https://test-issuer.example.com/');
    });

    it('should reject a token with invalid issuer', async () => {
      const app = new Hono<Env>();

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'https://wrong-issuer.example.com/') {
          return secret;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.get('/protected', (c) => {
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${validToken}`
        }
      }));

      expect(res.status).toBe(401);
    });

    it('should validate a token using issuerResolver', async () => {
      const app = new Hono<Env>();
      let userPayload: any = null;

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'https://test-issuer.example.com/') {
          return secret;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.get('/protected', (c) => {
        userPayload = c.get('user');
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${validToken}`
        }
      }));

      expect(res.status).toBe(200);
      expect(userPayload).not.toBeNull();
      expect(userPayload.sub).toBe('test-user');
      expect(userPayload.iss).toBe('https://test-issuer.example.com/');
    });
  });

  // Test for RS256 tokens
  describe('RS256 Tokens', () => {
    let validToken: string;
    let privateKey: jose.KeyLike;
    let publicKey: jose.KeyLike;

    beforeEach(async () => {
      // Import the keys
      privateKey = await jose.importPKCS8(RS256_PRIVATE_KEY, 'RS256');
      publicKey = await jose.importSPKI(RS256_PUBLIC_KEY, 'RS256');

      // Create a valid RS256 token
      validToken = await new jose.SignJWT({ sub: 'test-user', scope: 'read:data' })
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuedAt()
        .setIssuer('https://rs256-issuer.example.com/')
        .setExpirationTime('1h')
        .sign(privateKey);
    });

    it('should validate a valid RS256 token with string issuer', async () => {
      const app = new Hono<Env>();
      let userPayload: any = null;

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'https://rs256-issuer.example.com/') {
          return publicKey;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.get('/protected', (c) => {
        userPayload = c.get('user');
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${validToken}`
        }
      }));

      expect(res.status).toBe(200);
      expect(userPayload).not.toBeNull();
      expect(userPayload.sub).toBe('test-user');
      expect(userPayload.iss).toBe('https://rs256-issuer.example.com/');
    });

    it('should reject a token with invalid issuer', async () => {
      const app = new Hono();

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'wrong-issuer') {
          return publicKey;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.get('/protected', (c) => {
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${validToken}`
        }
      }));

      expect(res.status).toBe(401);
    });
  });

  // Test for requireScope middleware
  describe('requireScope Middleware', () => {
    const secret = new TextEncoder().encode('test-secret');
    let tokenWithScope: string;
    let tokenWithoutScope: string;

    beforeEach(async () => {
      // Create a token with scope
      tokenWithScope = await new jose.SignJWT({ sub: 'test-user', scope: 'read:data write:data' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('https://test-issuer.example.com/')
        .setExpirationTime('1h')
        .sign(secret);

      // Create a token without the required scope
      tokenWithoutScope = await new jose.SignJWT({ sub: 'test-user', scope: 'read:profile' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('https://test-issuer.example.com/')
        .setExpirationTime('1h')
        .sign(secret);
    });

    it('should allow access with required scope', async () => {
      const app = new Hono();

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'https://test-issuer.example.com/') {
          return secret;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.use('/protected', requireScope('read:data'));

      app.get('/protected', (c) => {
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${tokenWithScope}`
        }
      }));

      expect(res.status).toBe(200);
    });

    it('should deny access without required scope', async () => {
      const app = new Hono<Env>();

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'https://test-issuer.example.com/') {
          return secret;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.use('/protected', requireScope('write:data'));

      app.get('/protected', (c) => {
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${tokenWithoutScope}`
        }
      }));

      expect(res.status).toBe(403);
    });

    it('should handle scope as array', async () => {
      const app = new Hono<Env>();

      // Create a token with scope as array
      const tokenWithArrayScope = await new jose.SignJWT({ 
        sub: 'test-user', 
        scope: ['read:data', 'write:data'] 
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('https://test-issuer.example.com/')
        .setExpirationTime('1h')
        .sign(secret);

      const issuerResolver = async (issuer: string) => {
        if (issuer === 'https://test-issuer.example.com/') {
          return secret;
        }
        return null;
      };

      app.use('/protected', jwt({ 
        issuerResolver
      }));

      app.use('/protected', requireScope('write:data'));

      app.get('/protected', (c) => {
        return c.text('Protected');
      });

      const res = await app.fetch(new Request('https://example.com/protected', {
        headers: {
          'Authorization': `Bearer ${tokenWithArrayScope}`
        }
      }));

      expect(res.status).toBe(200);
    });
  });
});
