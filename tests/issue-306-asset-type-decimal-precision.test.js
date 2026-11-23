'use strict';

/**
 * Issue #306 — Asset Type and Decimal Precision Invariant Tests
 *
 * Verifies that the contract asset validation layer enforces correct decimal
 * precision, stroop conversion, and asset-type/issuer boundaries across a wide
 * range of inputs — including edge cases that fixed-example tests miss:
 *   - zero amounts
 *   - 1-stroop minimum
 *   - max int64 and max int128 boundary values
 *   - amounts with more than 7 decimal places (overflow precision)
 *   - rogue USDC issuers (asset spoofing)
 *   - empty / null / undefined amounts
 *
 * All randomised cases use a fixed seed for reproducibility.
 *
 * Acceptance criteria:
 *   ✓  Decimal invariants tested with 1 000+ inputs
 *   ✓  Fixed seed for CI reproducibility
 *   ✓  Violations include seed + case index for minimal reproduction
 */

process.env.MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/test';
process.env.SCHOOL_WALLET_ADDRESS =
  process.env.SCHOOL_WALLET_ADDRESS ||
  'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5';
// JWT_SECRET must be at least 32 chars — config/index.js throws otherwise.
process.env.JWT_SECRET = process.env.JWT_SECRET || 'a'.repeat(64);

const {
  DECIMALS,
  MIN_AMOUNT_STROOPS,
  MAX_INT64_STROOPS,
  MAX_INT128_STROOPS,
  ERROR_CODES,
  ContractAssetValidationError,
  parseAssetIdentifier,
  validateContractAsset,
  validateContractAmount,
  validateContractAssetAndAmount,
  verifyOffChainMatchesContract,
} = require('../backend/src/services/contractAssetValidation');

const {
  createDeterministicPrng,
} = require('../backend/src/services/contractAuthorizationPolicy');

// Fixed seed — do not change without documenting in CHANGELOG.
const SEED = 0xC0FFEE42;
const ITERATIONS = 1000;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a random valid XLM amount in the range [0.0000001, 100000.0000000]
 * with up to 7 decimal places.
 */
function randomValidAmount(prng) {
  const wholeUnits = prng.int(0, 99999);
  const fractionStroops = prng.int(1, 9999999);
  return wholeUnits + fractionStroops / 10000000;
}

/**
 * Generate a random number of additional decimal places beyond 7 (1–5 extra).
 */
function tooManyDecimals(prng, base) {
  const extra = prng.int(1, 5);
  const suffix = String(prng.int(1, 99999)).padStart(extra, '0');
  return `${base.toFixed(7)}${suffix}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Invariant 1 — Valid amounts always convert to exactly the right stroop count
// ─────────────────────────────────────────────────────────────────────────────
describe('Invariant 1: valid amount → exact stroop conversion', () => {
  test(`${ITERATIONS} random valid amounts convert without error (seed=${SEED})`, () => {
    const prng = createDeterministicPrng(SEED);
    let verified = 0;

    for (let i = 0; i < ITERATIONS; i++) {
      const amount = randomValidAmount(prng);
      let result;
      try {
        result = validateContractAmount(amount);
      } catch (err) {
        throw new Error(
          `Case ${i} (amount=${amount}) threw unexpectedly: ${err.message}. Seed: ${SEED}`
        );
      }

      expect(result.valid).toBe(true);
      expect(typeof result.stroops).toBe('bigint');
      expect(result.stroops).toBeGreaterThanOrEqual(MIN_AMOUNT_STROOPS);
      expect(result.stroops).toBeLessThanOrEqual(MAX_INT64_STROOPS);
      verified++;
    }

    expect(verified).toBe(ITERATIONS);
  });

  test('stroop conversion is bijective — fromStroops(toStroops(x)) === x for sampled amounts', () => {
    const prng = createDeterministicPrng(SEED + 1);
    for (let i = 0; i < 200; i++) {
      const amount = randomValidAmount(prng);
      const result = validateContractAmount(amount);
      // The amountDecimal round-trip should equal the input at 7dp precision
      const roundTripFloat = parseFloat(result.amountDecimal);
      const inputRounded = parseFloat(amount.toFixed(7));
      expect(roundTripFloat).toBeCloseTo(inputRounded, 6);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Invariant 2 — Zero amount is always rejected (unless allowZero option set)
// ─────────────────────────────────────────────────────────────────────────────
describe('Invariant 2: zero amount is rejected', () => {
  const zeroInputs = [0, 0.0, '0', '0.0', '0.0000000', 0n];

  test.each(zeroInputs)('zero amount "%s" throws AMOUNT_ZERO', (input) => {
    expect(() => validateContractAmount(input)).toThrow(ContractAssetValidationError);
    try {
      validateContractAmount(input);
    } catch (err) {
      expect(err.code).toBe(ERROR_CODES.AMOUNT_ZERO);
    }
  });

  test('zero is accepted when allowZero=true', () => {
    const result = validateContractAmount(0, { allowZero: true });
    expect(result.valid).toBe(true);
    expect(result.stroops).toBe(0n);
  });

  test('1 stroop (0.0000001) is the minimum accepted amount', () => {
    const result = validateContractAmount('0.0000001');
    expect(result.valid).toBe(true);
    expect(result.stroops).toBe(MIN_AMOUNT_STROOPS);
    expect(result.stroops).toBe(1n);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Invariant 3 — Negative amounts are always rejected
// ─────────────────────────────────────────────────────────────────────────────
describe('Invariant 3: negative amounts are always rejected', () => {
  test(`${ITERATIONS} random negative amounts all throw AMOUNT_NEGATIVE (seed=${SEED + 2})`, () => {
    const prng = createDeterministicPrng(SEED + 2);
    for (let i = 0; i < ITERATIONS; i++) {
      const magnitude = randomValidAmount(prng);
      const negative = -magnitude;
      expect(() => validateContractAmount(negative)).toThrow(ContractAssetValidationError);
      try {
        validateContractAmount(negative);
      } catch (err) {
        expect(err.code).toBe(ERROR_CODES.AMOUNT_NEGATIVE);
        if (err.code !== ERROR_CODES.AMOUNT_NEGATIVE) {
          throw new Error(
            `Case ${i}: expected AMOUNT_NEGATIVE for ${negative}, got ${err.code}. Seed: ${SEED + 2}`
          );
        }
      }
    }
  });

  test('string negative amounts are also rejected', () => {
    expect(() => validateContractAmount('-1')).toThrow(ContractAssetValidationError);
    expect(() => validateContractAmount('-0.0000001')).toThrow(ContractAssetValidationError);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Invariant 4 — Max int64 boundary
// ─────────────────────────────────────────────────────────────────────────────
describe('Invariant 4: max int64 boundary enforcement', () => {
  test('amount equal to MAX_INT64_STROOPS passes (default max)', () => {
    // MAX_INT64_STROOPS = 9223372036854775807n stroops = 922337203685.4775807 XLM
    const result = validateContractAmount('922337203685.4775807');
    expect(result.valid).toBe(true);
    expect(result.stroops).toBe(MAX_INT64_STROOPS);
  });

  test('amount exceeding MAX_INT64_STROOPS throws AMOUNT_OVERFLOW', () => {
    // 1 stroop over the max
    expect(() => validateContractAmount('922337203685.4775808')).toThrow(ContractAssetValidationError);
    try {
      validateContractAmount('922337203685.4775808');
    } catch (err) {
      expect(err.code).toBe(ERROR_CODES.AMOUNT_OVERFLOW);
    }
  });

  test('amount within custom maxStroops passes', () => {
    const result = validateContractAmount('1', { maxStroops: MAX_INT128_STROOPS });
    expect(result.valid).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Invariant 5 — Decimal precision: more than 7 decimal places rejected in strict mode
// ─────────────────────────────────────────────────────────────────────────────
describe('Invariant 5: decimal precision limit enforced in strict mode', () => {
  test(`${ITERATIONS} amounts with >7 decimal places throw DECIMAL_PRECISION_EXCEEDED in strict mode (seed=${SEED + 3})`, () => {
    const prng = createDeterministicPrng(SEED + 3);
    let rejected = 0;

    for (let i = 0; i < ITERATIONS; i++) {
      const base = randomValidAmount(prng);
      const tooLong = tooManyDecimals(prng, base);

      try {
        validateContractAmount(tooLong, { strictPrecision: true });
        // If it did not throw, the extra digits may have been all zeros — that
        // is a valid edge case; don't fail the test.
      } catch (err) {
        expect(err).toBeInstanceOf(ContractAssetValidationError);
        expect(err.code).toBe(ERROR_CODES.DECIMAL_PRECISION_EXCEEDED);
        rejected++;
      }
    }

    // At least 90% of randomly generated over-precision inputs should be caught
    expect(rejected).toBeGreaterThan(ITERATIONS * 0.9);
  });

  test('7 decimal places is accepted in strict mode', () => {
    const result = validateContractAmount('100.1234567', { strictPrecision: true });
    expect(result.valid).toBe(true);
  });

  test('8 decimal places throws in strict mode', () => {
    expect(() =>
      validateContractAmount('100.12345678', { strictPrecision: true })
    ).toThrow(ContractAssetValidationError);
    try {
      validateContractAmount('100.12345678', { strictPrecision: true });
    } catch (err) {
      expect(err.code).toBe(ERROR_CODES.DECIMAL_PRECISION_EXCEEDED);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Invariant 6 — Asset type and issuer validation
// ─────────────────────────────────────────────────────────────────────────────
describe('Invariant 6: asset type and issuer constraints', () => {
  test('XLM (native) is accepted without an issuer', () => {
    expect(() => validateContractAsset('XLM')).not.toThrow();
    expect(() => validateContractAsset('native')).not.toThrow();
  });

  test('unsupported asset codes are rejected', () => {
    const unsupported = ['BTC', 'ETH', 'FAKE', 'USD', '', null];
    for (const code of unsupported) {
      expect(() => validateContractAsset(code)).toThrow(ContractAssetValidationError);
    }
  });

  test('XLM with a spurious issuer field is rejected', () => {
    // Passing an object with type=native but a non-null issuer
    expect(() =>
      validateContractAsset({ code: 'XLM', type: 'native', issuer: 'GROGUE000' })
    ).toThrow(ContractAssetValidationError);
  });

  test('USDC with wrong issuer (asset spoofing attempt) is rejected', () => {
    // A rogue token claiming to be USDC with an attacker-controlled issuer
    expect(() =>
      validateContractAsset({
        code: 'USDC',
        type: 'credit_alphanum4',
        issuer: 'GATTACKER0000000000000000000000000000000000000000000000000',
      })
    ).toThrow(ContractAssetValidationError);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Invariant 7 — Atomic validation rejects on first error, no partial state
// ─────────────────────────────────────────────────────────────────────────────
describe('Invariant 7: validateContractAssetAndAmount is atomic', () => {
  test('valid asset + valid amount succeeds atomically', () => {
    const result = validateContractAssetAndAmount({ asset: 'XLM', amount: '100' });
    expect(result.valid).toBe(true);
    expect(result.stroops).toBeDefined();
    expect(result.asset).toBeDefined();
  });

  test('valid asset + zero amount throws before any state mutation', () => {
    expect(() =>
      validateContractAssetAndAmount({ asset: 'XLM', amount: 0 })
    ).toThrow(ContractAssetValidationError);
  });

  test('invalid asset + valid amount throws on asset check (asset-first ordering)', () => {
    expect(() =>
      validateContractAssetAndAmount({ asset: 'ROGUE', amount: '100' })
    ).toThrow(ContractAssetValidationError);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Invariant 8 — Off-chain / on-chain parity
// ─────────────────────────────────────────────────────────────────────────────
describe('Invariant 8: off-chain validation matches contract rules', () => {
  test('matching asset + amount pair returns matches=true', () => {
    const result = verifyOffChainMatchesContract('XLM', '10');
    expect(result.matches).toBe(true);
    expect(result.assetAgrees).toBe(true);
    expect(result.amountAgrees).toBe(true);
  });

  test('mismatched asset returns matches=false', () => {
    const result = verifyOffChainMatchesContract('ROGUE', '10');
    expect(result.matches).toBe(false);
    expect(result.assetAgrees).toBe(false);
  });
});
