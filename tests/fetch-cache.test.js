import test from 'node:test';
import assert from 'node:assert/strict';
import { FetchCache } from '../scripts/fetch-cache.js';

test('returns cached response within TTL (fetchFn called only once for two gets)', async () => {
    let callCount = 0;
    const fetchFn = async (url) => {
        callCount++;
        return { data: 'response', url };
    };
    const cache = new FetchCache({ fetchFn });

    const result1 = await cache.get('https://example.com/data', { ttlMs: 60000 });
    const result2 = await cache.get('https://example.com/data', { ttlMs: 60000 });

    assert.equal(callCount, 1);
    assert.deepEqual(result1, { data: 'response', url: 'https://example.com/data' });
    assert.deepEqual(result2, result1);
});

test('re-fetches after TTL expires', async () => {
    let callCount = 0;
    const fetchFn = async (url) => {
        callCount++;
        return { call: callCount };
    };
    const cache = new FetchCache({ fetchFn });

    const result1 = await cache.get('https://example.com/ttl', { ttlMs: 1 });
    assert.equal(callCount, 1);
    assert.deepEqual(result1, { call: 1 });

    await new Promise((resolve) => setTimeout(resolve, 10));

    const result2 = await cache.get('https://example.com/ttl', { ttlMs: 1 });
    assert.equal(callCount, 2);
    assert.deepEqual(result2, { call: 2 });
});

test('caches by URL (different URLs fetch separately)', async () => {
    const fetched = [];
    const fetchFn = async (url) => {
        fetched.push(url);
        return { url };
    };
    const cache = new FetchCache({ fetchFn });

    const r1 = await cache.get('https://example.com/a', { ttlMs: 60000 });
    const r2 = await cache.get('https://example.com/b', { ttlMs: 60000 });
    const r3 = await cache.get('https://example.com/a', { ttlMs: 60000 });
    const r4 = await cache.get('https://example.com/b', { ttlMs: 60000 });

    assert.equal(fetched.length, 2);
    assert.equal(fetched[0], 'https://example.com/a');
    assert.equal(fetched[1], 'https://example.com/b');
    assert.deepEqual(r1, { url: 'https://example.com/a' });
    assert.deepEqual(r2, { url: 'https://example.com/b' });
    assert.deepEqual(r3, r1);
    assert.deepEqual(r4, r2);
});

test('returns null on fetch error', async () => {
    const fetchFn = async (url) => {
        throw new Error('Network error');
    };
    const cache = new FetchCache({ fetchFn });

    const result = await cache.get('https://example.com/error', { ttlMs: 60000 });

    assert.equal(result, null);
});
