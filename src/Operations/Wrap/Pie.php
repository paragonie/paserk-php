<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\Wrap;

use ParagonIE\ConstantTime\{
    Base64,
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE\EasyECC\ECDSA\SecretKey;
use ParagonIE\Paserk\Operations\WrapInterface;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use Exception;
use SodiumException;
use function
    array_slice,
    chunk_split,
    explode,
    hash_equals,
    hash_hmac,
    implode,
    in_array,
    openssl_decrypt,
    openssl_encrypt,
    random_bytes;

/**
 * Class Pie
 * @package ParagonIE\Paserk\Operations\Wrap
 *
 * @link https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md
 */
class Pie implements WrapInterface
{
    const DOMAIN_SEPARATION_ENCRYPT = "\x80";
    const DOMAIN_SEPARATION_AUTH = "\x81";

    /** @var SymmetricKey $wrappingKey */
    protected $wrappingKey;

    /**
     * Pie constructor.
     * @param SymmetricKey $wrappingKey
     */
    public function __construct(SymmetricKey $wrappingKey)
    {
        $this->wrappingKey = $wrappingKey;
    }

    /**
     * @return string
     */
    public static function customId(): string
    {
        return 'pie';
    }

    /**
     * @return ProtocolInterface
     */
    public function getProtocol(): ProtocolInterface
    {
        return $this->wrappingKey->getProtocol();
    }

    /**
     * @param string $header
     * @param KeyInterface $key
     * @return string
     *
     * @throws Exception
     * @throws PaserkException
     * @throws SodiumException
     */
    public function wrapKey(string $header, KeyInterface $key): string
    {
        $this->throwIfVersionsMismatch($key->getProtocol());
        $protocol = $key->getProtocol();
        if ($protocol instanceof Version1 || $protocol instanceof Version3) {
            return $this->wrapKeyV1V3($header, $key);
        }
        if ($protocol instanceof Version2 || $protocol instanceof Version4) {
            return $this->wrapKeyV2V4($header, $key);
        }
        throw new PaserkException('Unknown key version');
    }

    /**
     * Wrap a key according to the PIE spec. V1/V3
     *
     * @ref https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v1v3-encryption
     *
     * @param string $header
     * @param KeyInterface $key
     * @return string
     * @throws Exception
     */
    protected function wrapKeyV1V3(string $header, KeyInterface $key): string
    {
        // Step 2:
        $n = random_bytes(32);

        // Step 3:
        $x = hash_hmac('sha384', self::DOMAIN_SEPARATION_ENCRYPT . $n, $this->wrappingKey->raw(), true);
        /// @SPEC DETAIL:                 ^ must be 0x80
        $Ek = Binary::safeSubstr($x, 0, 32);
        $n2 = Binary::safeSubstr($x, 32, 16);

        // Step 4:
        $Ak = Binary::safeSubstr(
            hash_hmac('sha384', self::DOMAIN_SEPARATION_AUTH . $n, $this->wrappingKey->raw(), true),
            /// @SPEC DETAIL:             ^ must be 0x81
            0,
            32
        );

        // Step 5:

        // This includes some PHP-specific behavior you may not need in other implementations:
        $rawKeyBytes = '' . $key->raw();
        if ($key->getProtocol() instanceof Version3 && Binary::safeStrlen($rawKeyBytes) !== 48) {
            // Get the raw scalar, not a PEM-encoded key
            $rawKeyBytes = Base64UrlSafe::decode($key->encode());
        }
        $c = openssl_encrypt(
            $rawKeyBytes,
            'aes-256-ctr',
            $Ek,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $n2
        );
        /// @SPEC DETAIL: Must use (Ek, n2)

        // Step 6:
        $t = hash_hmac(
            'sha384',
            $header . $n . $c,
            $Ak,
            true
        );
        /// @SPEC DETAIL: Must cover h || c || t, in that order.

        // Wipe keys from memory after use:
        Util::wipe($rawKeyBytes);
        Util::wipe($Ek);
        Util::wipe($n2);
        Util::wipe($x);
        Util::wipe($Ak);

        // Step 7:
        return Base64UrlSafe::encodeUnpadded($t . $n . $c);
        /// @SPEC DETAIL: Must return t || n || c (in that order)
    }

    /**
     * Wrap a key according to the PIE spec. V2/V4
     *
     * @ref https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-encryption
     *
     * @param string $header
     * @param KeyInterface $key
     * @return string
     *
     * @throws Exception
     * @throws SodiumException
     */
    protected function wrapKeyV2V4(string $header, KeyInterface $key): string
    {
        // Step 2:
        $n = random_bytes(32);

        // Step 3:
        $x = sodium_crypto_generichash(self::DOMAIN_SEPARATION_ENCRYPT . $n, $this->wrappingKey->raw(), 56);
        /// @SPEC DETAIL:               ^ Must be 0x80
        /// @SPEC DETAIL: Length MUST be 56 bytes
        $Ek = Binary::safeSubstr($x, 0, 32);
        $n2 = Binary::safeSubstr($x, 32, 24);

        // Step 4:
        $Ak = sodium_crypto_generichash(self::DOMAIN_SEPARATION_AUTH . $n, $this->wrappingKey->raw());
        /// @SPEC DETAIL:                ^ Must be 0x81

        // Step 5:
        $c = sodium_crypto_stream_xchacha20_xor($key->raw(), $n2, $Ek);
        /// @SPEC DETAIL: Must use (Ek, n2)

        // Step 6:
        $t = sodium_crypto_generichash($header . $n . $c, $Ak);

        // Wipe keys from memory after use:
        Util::wipe($Ek);
        Util::wipe($n2);
        Util::wipe($x);
        Util::wipe($Ak);

        // Step 7:
        return Base64UrlSafe::encodeUnpadded($t . $n . $c);
        /// @SPEC DETAIL: Must return t || n || c (in that order)
    }

    /**
     * Unwrap a key.
     *
     * @param string $wrapped
     * @return KeyInterface
     *
     * @throws PaserkException
     * @throws Exception
     */
    public function unwrapKey(string $wrapped): KeyInterface
    {
        // Algorithm Lucidity
        // First, assert the version is correct.
        $pieces = explode('.', $wrapped);
        $version = Util::getPasetoVersion($pieces[0]);
        $this->throwIfVersionsMismatch($version);

        // Make sure this wasn't wrapped using a different custom key-wrapping protocol:
        if (!hash_equals($pieces[2], self::customId())) {
            throw new PaserkException('Key is not wrapped with the PIE key-wrapping protocol');
        }
        $header = implode('.', array_slice($pieces, 0, 3)) . '.';
        if (in_array($pieces[0], ['k1', 'k3'], true)) {
            $bytes = $this->unwrapKeyV1V3($header, $pieces[3]);
            // Handle RSA private keys
            if ($pieces[0] === 'k1' && $pieces[1] === 'secret-wrap') {
                if (strpos($bytes, '-----BEGIN RSA PRIVATE KEY-----') !== 0) {
                    $b64 = Base64::encode($bytes);
                    $bytes = '-----BEGIN RSA PRIVATE KEY-----' . "\n" .
                        chunk_split($b64, 64, "\n") .
                        '-----END RSA PRIVATE KEY-----';
                }
                if (Binary::safeStrlen($bytes) < 1600) {
                    throw new PaserkException("Unwrapped RSA secret key is too small");
                }
                // If we're here, we have a valid PEM-encoded RSA private key.
            } elseif ($pieces[0] === 'k3' && $pieces[1] === 'secret-wrap') {
                if (Binary::safeStrlen($bytes) !== 48) {
                    throw new PaserkException("Unwrapped ECDSA secret key must be 48 bytes");
                }
                // If we're here, we have a valid ECDSA secret key.
            } elseif (Binary::safeStrlen($bytes) !== 32) {
                throw new PaserkException("Unwrapped local keys must be 32 bytes");
                // If we're here, we have a 256-bit symmetric key.
            }
        } elseif (in_array($pieces[0], ['k2', 'k4'], true)) {
            $bytes = $this->unwrapKeyV2V4($header, $pieces[3]);
            if ($pieces[1] === 'secret-wrap') {
                if (Binary::safeStrlen($bytes) !== 64) {
                    throw new PaserkException("Unwrapped Ed25519 secret keys must be 64 bytes");
                }
                // Ed25519 secret keys are encoded as (seed || pk), as per NaCl/libsodium.
            } elseif (Binary::safeStrlen($bytes) !== 32) {
                // This condition is only checked for local-wrap tokens
                throw new PaserkException("Unwrapped local keys must be 32 bytes");
            }
            // If we're here, we have a valid Ed25519 secret key or 256-bit symmetric key.
        } else {
            throw new PaserkException('Unknown version: ' . $pieces[0]);
        }

        if (hash_equals($pieces[1], 'local-wrap')) {
            return new SymmetricKey($bytes, $version);
        }
        if (hash_equals($pieces[1], 'secret-wrap')) {
            return new AsymmetricSecretKey($bytes, $version);
        }
        throw new PaserkException('Unknown wrapping type: ' . $pieces[1]);
    }

    /**
     * Unwrap a key according to the PIE spec. V1/V3
     *
     * @ref https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v1v3-decryption
     *
     * @param string $header
     * @param string $encoded
     * @return string
     * @throws PaserkException
     */
    protected function unwrapKeyV1V3(string $header, string $encoded): string
    {
        // Step 1:
        $decoded = Base64UrlSafe::decode($encoded);
        $t = Binary::safeSubstr($decoded,  0, 48);
        /// @SPEC DETAIL: The first 48 bytes will be `t`
        $n = Binary::safeSubstr($decoded, 48, 32);
        /// @SPEC DETAIL: The next 32 bytes will be the nonce `n`
        $c = Binary::safeSubstr($decoded, 80);
        /// @SPEC DETAIL: The remaining bytes will be the wrapped key

        // Step 2:
        $Ak = Binary::safeSubstr(
            hash_hmac(
                'sha384',
                self::DOMAIN_SEPARATION_AUTH . $n,
                $this->wrappingKey->raw(),
                true
            ),
            /// @SPEC DETAIL: Must be 0x81
            0,
            32
        );

        // Step 3:
        $t2 = hash_hmac(
            'sha384',
            $header . $n . $c,
            $Ak,
            true
        );

        // Step 4:
        if (!hash_equals($t2, $t)) {
            Util::wipe($t2);
            Util::wipe($Ak);
            throw new PaserkException('Invalid authentication tag');
        }
        /// @SPEC DETAIL: Must be a constant-time comparison.

        // Step 5:
        $x = hash_hmac('sha384', self::DOMAIN_SEPARATION_ENCRYPT . $n, $this->wrappingKey->raw(), true);
        /// @SPEC DETAIL:                  ^ Must be 0x80
        $Ek = Binary::safeSubstr($x, 0, 32);
        $n2 = Binary::safeSubstr($x, 32, 16);

        // Step 6:
        $ptk = openssl_decrypt(
            $c,
            'aes-256-ctr',
            $Ek,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $n2
        );

        // Wipe keys from memory after use:
        Util::wipe($Ek);
        Util::wipe($n2);
        Util::wipe($x);
        Util::wipe($Ak);
        return $ptk;
    }

    /**
     * Unwrap a key according to the PIE spec. V2/V4
     *
     * @ref https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md#v2v4-decryption
     *
     * @param string $header
     * @param string $encoded
     * @return string
     *
     * @throws PaserkException
     * @throws SodiumException
     */
    protected function unwrapKeyV2V4(string $header, string $encoded): string
    {
        // Step 1:
        $decoded = Base64UrlSafe::decode($encoded);
        $t = Binary::safeSubstr($decoded,  0, 32);
        /// @SPEC DETAIL: The first 32 bytes will be `t`
        $n = Binary::safeSubstr($decoded, 32, 32);
        /// @SPEC DETAIL: The next 32 bytes will be the nonce `n`
        $c = Binary::safeSubstr($decoded, 64);
        /// @SPEC DETAIL: The remaining bytes will be the wrapped key

        // Step 2:
        $Ak = sodium_crypto_generichash(self::DOMAIN_SEPARATION_AUTH . $n, $this->wrappingKey->raw());
        /// @SPEC DETAIL:                ^ Must be 0x81

        // Step 3:
        $t2 = sodium_crypto_generichash($header . $n . $c, $Ak);

        // Step 4:
        if (!hash_equals($t2, $t)) {
            Util::wipe($t2);
            Util::wipe($Ak);
            throw new PaserkException('Invalid authentication tag');
        }
        /// @SPEC DETAIL: Must be a constant-time comparison.

        // Step 5:
        $x = sodium_crypto_generichash(self::DOMAIN_SEPARATION_ENCRYPT . $n, $this->wrappingKey->raw(), 56);
        /// @SPEC DETAIL:               ^ Must be 0x80
        $Ek = Binary::safeSubstr($x, 0, 32);
        $n2 = Binary::safeSubstr($x, 32, 24);

        // Step 6:
        $ptk = sodium_crypto_stream_xchacha20_xor($c, $n2, $Ek);
        // Wipe keys from memory after use:
        Util::wipe($Ek);
        Util::wipe($n2);
        Util::wipe($x);
        Util::wipe($Ak);
        returN $ptk;
    }

    /**
     * @param ProtocolInterface $given
     * @throws PaserkException
     */
    private function throwIfVersionsMismatch(ProtocolInterface $given): void
    {
        $expect = $this->wrappingKey->getProtocol();
        if (!hash_equals($expect::header(), $given::header())) {
            throw new PaserkException('Invalid key version.');
        }
    }
}
