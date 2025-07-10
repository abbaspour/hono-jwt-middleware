// noinspection DuplicatedCode

import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import {IssuerResolver, jwt, requireScope} from '../src/index';
import * as jose from 'jose';
import {type JWTHeaderParameters, JWTPayload} from 'jose';

interface Env {
  Variables: {
    user: JWTPayload;
    jwtHeader: JWTHeaderParameters;
  };
}

// Hard-coded keys for RS256 testing - run make keypair for a new set of keys
const RS256_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDfOLQvUF9mCXDk
7xJMQalk1O+gZAQkeenS2wrnGKRPc5/VkCNNEENEPFIUiNduLS4byU9Qi936RDjy
pLB+I5fshx3OrmcuVSVyD7xKSfOVmhy8Z+8u/nkhZfNcBTznHO0Q+n4ZqSrKlm0a
oQHLXfx55U4AwAyK/NlfZigG0pJgn5Sm+vFPqtYcw2bWd7oTqOtJinjERyVEDAGs
1d/6WKsE+kd861P1IHTNmeuBg+0sakFXUjGi+LniEGK0PcOymhLvcmVYxu+3d92L
ixQGlNlNEsBiHsvIoZ40carPu7IVaV/P27LUN5rY1NbmIMhNm5gArWbvIKlxB+5t
hsQaxYxXAgMBAAECggEAKrOVPIvahBGASDs3u+C/v+tAH+WiKTwtL8n5TvYW0KAk
zlzxc9eNlqsXZJg85fW8oVIkWxs2jp6oajp5DNhQQs4iNJyGXoWpUSWTdn6pG1BM
+PnE9q91ip8PK+ZQnUGaVConH0+OQQz/uB1e04GaP9NO1bPnclsmViqbs5pqqBLj
iVvdRfg6fsLCCRiQuZ/TgatpsGmDIq1+WgJO3KHZWoPKMLtKcC5nT3DAZi+lJQ8X
7nHe8aoY5xK7Kwg7pz9fm4W2XF3rleymZDYF64gZu70uFwVs+O7s0nLH5sIoQtK0
xtvz1AjuDQZcOL80qhP8QlG09zM1KW3LDX8Jeg+EYQKBgQDz+KlaRb/3jvHdEWzU
71ciwYLxEC18H5+TyLt4KoBts/ByI4/A+g91Ow9igFrWjgyBt9v+lwhUZBk9XeaL
9WNuY6owlxUl6ixkCzoORJwcst9aszIqcK8mOQ/Lf+sMfXhK2vKGYOsJxIcK/0nq
OkQEKLIO7NOJ5L2Ps0JYEip5kQKBgQDqOiTGzbCfj1MLDITn1ViE5EQl/9+D2i+E
YhQOw298yyT6HTEeUGxi4Dx+saVVqOsSjl/kr5Sej6043PqkUg0STaOI8eD/0JkV
OT96uuK4Eo4voO0pSiVHDJAyeDlg3JfLmRwq609NGoDHcrRe1eLp5+jmK/6VDLCK
J3LlwKrzZwKBgQDT2yTEvTj78mdY/x6wsb3K8puQVeoJlTRvkqooqU+o885ibzsP
6pWtyUGM2cUH94Yoxs4FAIY9MkcwoO/orYhQfb92Plwg9n7hyVX6ud2Olk2aZ22y
qPOPj5GFt2kXCYWCCyr7QgIYE07pX9KB0WLq8aPdjg4L+lQaCyIbdHrp4QKBgDPx
rRJBr3fTSzFaF2dqkvT1wn9C3YjaLEuJjLUxdloQmyS0sJ3ua/sJi6D1OJtkmK1G
0dFfdvArINlJeHRUlf2HJktKiQFye2CPj5piM8FqrAm4AKB1hwrYqGno66Cliyxl
yi9ie/W3ePPCZmnZuTbybV4OR6k6ZTReR0bYkZDlAoGBAMv7alO7a8U5o3BUBvg2
gD5zFTwNGfqrJa/J2JlUxg+QnbmA9HwiHfSAXNON2Wb0jx0pZCsX26rYOiJbofOG
dCl6B2yBWpPaPlMNrQ48ZTuZBvOYkxnN7csEq7yoXSW1mBuL8peLNSFV3Il/S5HN
NQWCvSgP6B0SnyJqBndZGYXA
-----END PRIVATE KEY-----`;

const RS256_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3zi0L1BfZglw5O8STEGp
ZNTvoGQEJHnp0tsK5xikT3Of1ZAjTRBDRDxSFIjXbi0uG8lPUIvd+kQ48qSwfiOX
7Icdzq5nLlUlcg+8SknzlZocvGfvLv55IWXzXAU85xztEPp+GakqypZtGqEBy138
eeVOAMAMivzZX2YoBtKSYJ+UpvrxT6rWHMNm1ne6E6jrSYp4xEclRAwBrNXf+lir
BPpHfOtT9SB0zZnrgYPtLGpBV1Ixovi54hBitD3DspoS73JlWMbvt3fdi4sUBpTZ
TRLAYh7LyKGeNHGqz7uyFWlfz9uy1Dea2NTW5iDITZuYAK1m7yCpcQfubYbEGsWM
VwIDAQAB
-----END PUBLIC KEY-----  `;

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

      const issuerResolver : IssuerResolver = async (issuer: string) => {
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
      if(userPayload == null) { throw new Error('userPayload is null'); }
      expect(userPayload.sub).toBe('test-user');
      expect(userPayload.iss).toBe('https://test-issuer.example.com/');
    });

    it('should validate a valid HS256 token with array of issuers', async () => {
      const app = new Hono<Env>();
      let userPayload: JWTPayload | null = null;

      const issuerResolver : IssuerResolver = async (issuer: string) => {
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

      const issuerResolver : IssuerResolver = async (issuer: string) => {
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

      const issuerResolver : IssuerResolver = async (issuer: string) => {
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

      const issuerResolver: IssuerResolver = async (issuer: string) => {
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

      const issuerResolver : IssuerResolver = async (issuer: string) => {
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

      const issuerResolver: IssuerResolver = async (issuer: string) => {
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
