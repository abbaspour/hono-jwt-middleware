import { vi } from 'vitest';

// Mock the isCloudflareWorkers function to return false for tests
vi.mock('../src/index', async (importOriginal) => {
  const mod = await importOriginal();
  return {
    ...mod,
    // Override internal functions for testing
    isCloudflareWorkers: () => false,
  };
});

// Mock fetch for tests
if (!globalThis.fetch) {
  // @ts-ignore
  globalThis.fetch = vi.fn().mockResolvedValue(new Response('{}'));
}

// Define a mock cache for Cloudflare
if (!('caches' in globalThis)) {
  // @ts-ignore
  globalThis.caches = {
    default: {
      match: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined)
    }
  };
}
