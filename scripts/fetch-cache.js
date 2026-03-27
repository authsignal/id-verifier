export class FetchCache {
    constructor({ fetchFn }) {
        this._fetchFn = fetchFn;
        this._cache = new Map();
    }

    async get(url, { ttlMs }) {
        const entry = this._cache.get(url);
        if (entry && (Date.now() - entry.timestamp) < ttlMs) {
            return entry.value;
        }
        try {
            const value = await this._fetchFn(url);
            this._cache.set(url, { value, timestamp: Date.now() });
            return value;
        } catch (err) {
            console.error(`FetchCache: error fetching ${url}:`, err);
            return null;
        }
    }

    clear() {
        this._cache.clear();
    }

    invalidate(url) {
        this._cache.delete(url);
    }
}
