/**
 * True when the value is a well-formed Bitwarden EncString for its type.
 *
 * Bitwarden EncString wire format (per bitwarden/sdk-internal
 * crates/bitwarden-crypto/src/enc_string):
 *   - type 0: legacy AES-256-CBC                       -> "iv|data"           (2 parts)
 *   - type 1: removed AesCbc128_HmacSha256_B64, kept on the wire for
 *             backward compatibility                   -> "iv|data"           (2 parts)
 *   - type 2: authenticated AES-256-CBC-HMAC-SHA256    -> "iv|data|mac"       (3 parts)
 *   - type 4: RSA-2048-OAEP-SHA1 (single segment)     -> "data"              (1 part)
 *   - type 5: RSA-2048-OAEP-SHA256-HMAC-SHA256 (deprecated) -> "data|mac"   (2 parts)
 *   - type 6: RSA-2048-OAEP-SHA1-HMAC-SHA256 (deprecated)   -> "data|mac"   (2 parts)
 *   - type 7: COSE_Encrypt0_B64                       -> "cose_bytes"        (1 part)
 * Each spec-defined type has a fixed arity; the Rust parser rejects any other
 * arity as EncStringParseError. Unknown types are kept future-compatible with
 * at least one part so new upstream variants don't get silently dropped.
 */
export function isValidEncString(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  const dot = trimmed.indexOf('.');
  if (dot <= 0) return false;
  const type = Number(trimmed.slice(0, dot));
  if (!Number.isInteger(type) || type < 0) return false;
  const parts = trimmed.slice(dot + 1).split('|');
  if (parts.some((part) => part.length === 0)) return false;

  if (type === 0 || type === 1) return parts.length === 2;
  if (type === 2) return parts.length === 3;
  if (type === 4 || type === 7) return parts.length === 1;
  if (type === 5 || type === 6) return parts.length === 2;
  return parts.length >= 1;
}
