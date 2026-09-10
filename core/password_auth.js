import crypto from 'crypto';

const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 3;
const KEY_LENGTH = 64;
const MAX_PASSWORD_BYTES = 1024;

function derive(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, KEY_LENGTH, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 128 * 1024 * 1024 }, (err, key) => {
            if (err) return reject(err);
            resolve(key);
        });
    });
}

export async function hashPassword(password) {
    if (typeof password !== 'string' || password.length < 12) throw new Error('Password must be at least 12 characters.');
    if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) throw new Error('Password is too long.');
    const salt = crypto.randomBytes(16);
    const key = await derive(password, salt);
    return `scrypt$N=${SCRYPT_N},r=${SCRYPT_R},p=${SCRYPT_P}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(password, encoded) {
    if (typeof password !== 'string' || typeof encoded !== 'string') return false;
    const parts = encoded.split('$');
    if (parts.length !== 4 || parts[0] !== 'scrypt') return false;
    const params = Object.fromEntries(parts[1].split(',').map(item => item.split('=')));
    const n = Number(params.N), r = Number(params.r), p = Number(params.p);
    if (!Number.isSafeInteger(n) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p) || n <= 1 || r <= 0 || p <= 0) return false;
    const salt = Buffer.from(parts[2], 'base64url');
    const expected = Buffer.from(parts[3], 'base64url');
    if (!salt.length || expected.length !== KEY_LENGTH) return false;
    try {
        const actual = await new Promise((resolve, reject) => {
            crypto.scrypt(password, salt, expected.length, { N: n, r, p, maxmem: 128 * 1024 * 1024 }, (err, key) => err ? reject(err) : resolve(key));
        });
        return crypto.timingSafeEqual(actual, expected);
    } catch {
        return false;
    }
}
