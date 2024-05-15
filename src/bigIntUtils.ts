/**
 * Returns the smallest positive value in the multiplicative group of integers
 * modulo n that is congruent to a.
 *
 * @param {bigint} a value to find congruent value of
 * @param {bigint} n modulo of multiplicative group
 * @return {bigint} smallest positive congruent value of a in integers modulo n
 */
function toZn(a: bigint, n: bigint): bigint {
  if (n < 1n) {
    throw new RangeError("n must be > 0");
  }

  const aZn = a % n;
  return aZn < 0n ? aZn + n : aZn;
}

/**
 * Solves for values g, x, y, such that g = gcd(a, b) and g = ax + by.
 *
 * @param {bigint} a
 * @param {bigint} b
 * @return {{g: bigint, x: bigint, y: bigint }}
 */
function eGcd(
  a: bigint,
  b: bigint
): {
  g: bigint;
  x: bigint;
  y: bigint;
} {
  if (a < 1n || b < 1n) {
    throw new RangeError("a and b must be > 0");
  }

  let x = 0n;
  let y = 1n;
  let u = 1n;
  let v = 0n;

  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }

  return { g: b, x, y };
}

/**
 * Calculates the modular inverse of a in the multiplicative group of integers
 * modulo n.
 *
 * @param {bigint} a
 * @param {bigint} n
 * @return {bigint}
 */
function modInv(a: bigint, n: bigint): bigint {
  const egcd = eGcd(toZn(a, n), n);
  if (egcd.g !== 1n) {
    throw new RangeError();
  } else {
    return toZn(egcd.x, n);
  }
}

/**
 * Calculates the value of x ^ y % m efficiently.
 *
 * @param {bigint} x
 * @param {bigint} y
 * @param {bigint} m
 * @return {bigint}
 */
export function modPow(x: bigint, y: bigint, m: bigint): bigint {
  if (m < 1n) {
    throw new RangeError("n must be > 0");
  } else if (m === 1n) {
    return 0n;
  }

  x = toZn(x, m);

  if (y < 0n) {
    return modInv(modPow(x, y >= 0 ? y : -y, m), m);
  }

  let r = 1n;
  while (y > 0) {
    if (y % 2n === 1n) {
      r = (r * x) % m;
    }
    y = y / 2n;
    x = x ** 2n % m;
  }
  return r;
}
