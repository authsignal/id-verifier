import test from 'node:test';
import assert from 'node:assert/strict';
import { getStatusFromBitstring, checkTokenStatusList } from '../scripts/status-list-helper.js';
import pako from 'pako';

test('getStatusFromBitstring checks the correct bit index (1-bit)', () => {
    // Create a bitstring where index 5 is revoked (bit set to 1)
    const bits = new Uint8Array(2); // 16 indices
    bits[0] = 0b00000100; // index 5 from MSB (bit position 5 = 0b00000100)
    const compressed = pako.deflate(bits);
    const base64 = Buffer.from(compressed).toString('base64url');

    assert.equal(getStatusFromBitstring(base64, 5, 1), 1, 'Index 5 should be revoked');
    assert.equal(getStatusFromBitstring(base64, 0, 1), 0, 'Index 0 should not be revoked');
    assert.equal(getStatusFromBitstring(base64, 4, 1), 0, 'Index 4 should not be revoked');
});

test('getStatusFromBitstring supports 2-bit status entries', () => {
    // 2 bits per entry: 4 entries per byte
    // For entry 1 (bits 2-3): set to 0b10 = 2
    const bits = new Uint8Array(1);
    bits[0] = 0b00100000; // entry 0 = 00, entry 1 = 10, entry 2 = 00, entry 3 = 00
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
