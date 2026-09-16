/** @typedef {import('../db.js').Database} Database */
/** @typedef {import('../types.js').EventRow} EventRow */

/** Append-only security audit log. */
export class EventStore {
  static COLUMNS = 'id, user_id, type, ip, meta, at';

  /** @param {Database} db */
  constructor(db) {
    const C = EventStore.COLUMNS;
    this.stmt = {
      insert: db.prepare(`INSERT INTO events (user_id, type, ip, meta, at) VALUES (?, ?, ?, ?, ?)`),
      forUser: db.prepare(`SELECT ${C} FROM events WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT ?`),
      purge: db.prepare(`DELETE FROM events WHERE at < ?`),
    };
  }

  /**
   * @param {{ userId?: string|null, type: string, ip?: string|null, meta?: object|null }} e
   * @param {number} [now]
   */
  record({ userId = null, type, ip = null, meta = null }, now = Date.now()) {
    this.stmt.insert.run(userId, type, ip, meta ? JSON.stringify(meta) : null, now);
  }

  /**
   * Newest first, keyset pagination on id.
   * @param {string} userId
   * @param {{ limit: number, beforeId?: number }} q
   * @returns {EventRow[]}
   */
  forUser(userId, { limit, beforeId = Number.MAX_SAFE_INTEGER }) {
    return /** @type {EventRow[]} */ (this.stmt.forUser.all(userId, beforeId, limit));
  }

  /** @param {number} before */
  purge(before) {
    return Number(this.stmt.purge.run(before).changes);
  }
}
