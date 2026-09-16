/** Password acceptance rules. Returns human-readable problems instead of throwing. */
export class PasswordPolicy {
  static MAX_LENGTH = 256;

  /** Most common leaked passwords; a small, fast denylist. */
  static DENYLIST = new Set([
    '123456', '123456789', '12345678', '1234567890', 'password', 'password1', 'password123', 'qwerty', 'qwerty123',
    'qwertyuiop', '111111', '123123', '1234567', 'abc123', 'iloveyou', 'admin', 'admin123', 'welcome', 'welcome1',
    'letmein', 'monkey', 'dragon', 'football', 'baseball', 'sunshine', 'princess', 'passw0rd', 'p@ssw0rd', 'master',
    'login', 'trustno1', 'starwars', 'hello123', 'freedom', 'whatever', 'qazwsx', 'zaq12wsx', '1q2w3e4r', '1qaz2wsx',
    'superman', 'michael', 'shadow', 'ashley', 'charlie', 'donald', 'jennifer', 'jordan', 'batman', 'liverpool',
    'sifre123', 'parola123', 'sifre1234', 'parola', '159753', '987654321', '000000', '654321', 'aaaaaa', 'asdfgh',
  ]);

  /** @param {{ minLength: number }} o */
  constructor({ minLength }) {
    this.minLength = minLength;
  }

  /**
   * @param {string} password
   * @param {{ email?: string }} [ctx]
   * @returns {string[]} Empty when acceptable.
   */
  problems(password, { email } = {}) {
    const problems = [];
    const chars = [...password].length;
    if (chars < this.minLength) problems.push(`must be at least ${this.minLength} characters`);
    if (chars > PasswordPolicy.MAX_LENGTH) problems.push(`must be at most ${PasswordPolicy.MAX_LENGTH} characters`);
    if (/^\s|\s$/.test(password)) problems.push('must not start or end with whitespace');
    const lower = password.toLowerCase();
    const compact = lower.replace(/[^a-z0-9@]/g, '');
    // Also catch the classic "common word + a few digits/symbols" variants (password1234, qwerty2024!).
    const stem = compact.replace(/[0-9]{1,6}$/, '');
    if (PasswordPolicy.DENYLIST.has(compact) || (stem.length >= 5 && PasswordPolicy.DENYLIST.has(stem))) problems.push('is too common');
    if (/^(.)\1+$/.test(password)) problems.push('must not repeat a single character');
    if (email) {
      const e = email.toLowerCase();
      const local = e.split('@')[0];
      if (lower === e || (local.length >= 4 && lower.includes(local))) problems.push('must not contain your email address');
    }
    return problems;
  }
}
