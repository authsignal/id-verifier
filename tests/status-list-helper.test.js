import test from 'node:test';
import assert from 'node:assert/strict';
import { getStatusFromBitstring, checkTokenStatusList } from '../scripts/status-list-helper.js';
import pako from 'pako';

test('getStatusFromBitstring checks the correct bit index (1-bit, LSB-first)', () => {
    // RFC 9597: bit position starts from LSB
    // Index 5 = bit 5 from LSB = 0b00100000
    const bits = new Uint8Array(2);
    bits[0] = 0b00100000; // index 5 set (bit 5 from LSB)
    const compressed = pako.deflate(bits);
    const base64 = Buffer.from(compressed).toString('base64url');

    assert.equal(getStatusFromBitstring(base64, 5, 1), 1, 'Index 5 should be revoked');
    assert.equal(getStatusFromBitstring(base64, 0, 1), 0, 'Index 0 should not be revoked');
    assert.equal(getStatusFromBitstring(base64, 4, 1), 0, 'Index 4 should not be revoked');
    assert.equal(getStatusFromBitstring(base64, 6, 1), 0, 'Index 6 should not be revoked');
});

test('getStatusFromBitstring supports 2-bit status entries (LSB-first)', () => {
    // RFC 9597 LSB-first: 2 bits per entry, 4 entries per byte
    // Entry 0 = bits 0-1, Entry 1 = bits 2-3, Entry 2 = bits 4-5, Entry 3 = bits 6-7
    // Set entry 1 to value 2 (0b10): bits 2-3 = 10 → byte = 0b00001000
    const bits = new Uint8Array(1);
    bits[0] = 0b00001000; // entry 1 = 0b10 = 2 (bits 2-3 from LSB)
    const compressed = pako.deflate(bits);
    const base64 = Buffer.from(compressed).toString('base64url');

    assert.equal(getStatusFromBitstring(base64, 0, 2), 0, 'Entry 0 should be 0');
    assert.equal(getStatusFromBitstring(base64, 1, 2), 2, 'Entry 1 should be 2');
    assert.equal(getStatusFromBitstring(base64, 2, 2), 0, 'Entry 2 should be 0');
});

test('checkTokenStatusList returns statusListRef when disabled', async () => {
    const statusListRef = { uri: 'https://issuer.example/status/1', index: 42 };
    const result = await checkTokenStatusList(statusListRef, { enabled: false });
    assert.equal(result.revoked, false);
    assert.deepEqual(result.statusListRef, statusListRef);
});
