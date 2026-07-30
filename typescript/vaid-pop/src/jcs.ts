/**
 * RFC 8785 (JSON Canonicalization Scheme) serialization.
 *
 * This is the byte-identity primitive. The Rust crates reach it through
 * `serde_jcs`, the Python packages through `rfc8785`; this is the TypeScript
 * implementation, and it is deliberately dependency-free because the whole point
 * of the package is that a third language reproduces the frozen vectors — a
 * canonicalizer we cannot read is a canonicalizer we cannot vouch for.
 *
 * JavaScript is the easy language to do this in, because RFC 8785 defines
 * canonical JSON *in terms of* ECMAScript:
 *
 * - **Number serialization** is ECMAScript `Number::toString`, which is exactly
 *   what `JSON.stringify` emits for a finite number (RFC 8785 §3.2.2.3).
 * - **String serialization** is ECMAScript `JSON.stringify` escaping: the short
 *   escapes for `"`, `\`, and the five whitespace controls, `\u00xx` for the
 *   remaining C0 range, no escaping of anything else, and lone surrogates
 *   emitted as `\udxxx` (well-formed `JSON.stringify`, ES2019) (§3.2.2.2).
 * - **Object key ordering** is by UTF-16 code unit, which is precisely what
 *   JavaScript's default string comparison and `Array.prototype.sort` do
 *   (§3.2.3).
 *
 * So the correct implementation is a recursive walk that sorts keys and defers
 * to `JSON.stringify` for the scalars. What `JSON.stringify` alone would get
 * wrong — and the only reasons this function exists — are key ordering and the
 * silent dropping of values it cannot represent.
 *
 * Rejected rather than coerced, because each would silently change signed bytes:
 * `undefined`, functions, and symbols as *array elements* (`JSON.stringify`
 * turns them into `null`); `NaN`/`Infinity` (`JSON.stringify` turns them into
 * `null`); `bigint` (`JSON.stringify` throws, but with a less useful message).
 * An `undefined` *object property* is omitted, matching both `JSON.stringify`
 * and serde's `skip_serializing_if`/`Option` handling for an absent field.
 */

/** Any value this canonicalizer accepts. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue | undefined };

/**
 * The RFC 8785 canonical UTF-8 bytes of `value`.
 *
 * This is the input to SHA-256 everywhere in VAID. Callers that want the string
 * form can use {@link canonicalizeToString}.
 */
export function canonicalize(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalizeToString(value));
}

/** The RFC 8785 canonical form of `value` as a string. */
export function canonicalizeToString(value: unknown): string {
  const out: string[] = [];
  serialize(value, out);
  return out.join('');
}

function serialize(value: unknown, out: string[]): void {
  if (value === null) {
    out.push('null');
    return;
  }

  switch (typeof value) {
    case 'boolean':
      out.push(value ? 'true' : 'false');
      return;

    case 'number':
      // JSON has no NaN/Infinity; JSON.stringify would emit `null` and change
      // the signed bytes without telling anyone. Refuse instead.
      if (!Number.isFinite(value)) {
        throw new JcsError(`cannot canonicalize a non-finite number: ${value}`);
      }
      // ECMAScript Number::toString is exactly RFC 8785 §3.2.2.3. Note that
      // `JSON.stringify(-0)` is "0", which is also what RFC 8785 requires.
      out.push(JSON.stringify(value));
      return;

    case 'string':
      // ES JSON string escaping is verbatim RFC 8785 §3.2.2.2.
      out.push(JSON.stringify(value));
      return;

    case 'bigint':
      throw new JcsError(
        'cannot canonicalize a bigint — RFC 8785 numbers are IEEE-754 doubles; ' +
          'encode large integers as strings, as the VAID documents do',
      );

    case 'object':
      break;

    default:
      // undefined, function, symbol
      throw new JcsError(`cannot canonicalize a value of type ${typeof value}`);
  }

  if (Array.isArray(value)) {
    out.push('[');
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out.push(',');
      // JSON.stringify would coerce a hole or an `undefined` element to `null`.
      // Silently substituting a value inside signed bytes is the failure mode
      // this whole module exists to prevent.
      if (value[i] === undefined) {
        throw new JcsError(`array element ${i} is undefined — refusing to coerce it to null`);
      }
      serialize(value[i], out);
    }
    out.push(']');
    return;
  }

  // Plain object. Keys sort by UTF-16 code unit (RFC 8785 §3.2.3) — the default
  // JavaScript string ordering, so a bare `.sort()` is the specified ordering
  // and not merely a convenient one.
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort();

  out.push('{');
  for (let i = 0; i < keys.length; i++) {
    if (i > 0) out.push(',');
    out.push(JSON.stringify(keys[i]));
    out.push(':');
    serialize(record[keys[i]], out);
  }
  out.push('}');
}

/** A value that cannot be canonicalized under RFC 8785. */
export class JcsError extends Error {
  override readonly name = 'JcsError';
}
