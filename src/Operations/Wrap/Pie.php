<?php
declare(strict_types=1);

namespace ParagonIE\Paserk\Operations\Wrap;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paserk\Operations\WrapInterface;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};

/**
 * Class Pie
 * @package ParagonIE\Paserk\Operations\Wrap
 *
 * @link https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md
 */
class Pie implements WrapInterface
{
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
     * @param string $header
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
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
     * @param string $header
     * @param KeyInterface $key
     * @return string
     * @throws \Exception
     */
    protected function wrapKeyV1V3(string $header, KeyInterface $key): string
    {
        // Step 1:
        $n = random_bytes(32);

        // Step 2:
        $x = hash_hmac('sha384', "\x80" . $n, $this->wrappingKey->raw(), true);
        $Ek = Binary::safeSubstr($x, 0, 32);
        $n2 = Binary::safeSubstr($x, 32, 16);

        // Step 3:
        $Ak = Binary::safeSubstr(
            hash_hmac('sha384', "\x81" . $n, $this->wrappingKey->raw(), true),
            0,
            32
        );

        // Step 4:
        $c = \openssl_encrypt(
            $key->raw(),
            'aes-256-ctr',
            $Ek,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $n2
        );

        // Step 5:
        $t = hash_hmac(
            'sha384',
            $header . $n . $c,
            $Ak,
            true
        );

        // Wipe keys from memory after use:
        try {
            sodium_memzero($Ek);
            sodium_memzero($n2);
            sodium_memzero($x);
            sodium_memzero($Ak);
        } catch (\SodiumException $ex) {
            $Ek ^= $Ek;
            $n2 ^= $n2;
            $x ^= $x;
            $Ak ^= $Ak;
        }

        // Step 6:
        return Base64UrlSafe::encodeUnpadded($t . $n . $c);
    }

    /**
     * @param string $header
     * @param KeyInterface $key
     * @return string
     */
    protected function wrapKeyV2V4(string $header, KeyInterface $key): string
    {
        // Step 1:
        $n = random_bytes(32);

        // Step 2:
        $x = sodium_crypto_generichash("\x80" . $n, $this->wrappingKey->raw(), 56);
        $Ek = Binary::safeSubstr($x, 0, 32);
        $n2 = Binary::safeSubstr($x, 32, 24);

        // Step 3:
        $Ak = sodium_crypto_generichash("\x81" . $n, $this->wrappingKey->raw());

        // Step 4:
        $c = sodium_crypto_stream_xchacha20_xor($key->raw(), $n2, $Ek);

        // Step 5:
        $t = sodium_crypto_generichash($header . $n . $c, $Ak);

        // Wipe keys from memory after use:
        try {
            sodium_memzero($Ek);
            sodium_memzero($n2);
            sodium_memzero($x);
            sodium_memzero($Ak);
        } catch (\SodiumException $ex) {
            $Ek ^= $Ek;
            $n2 ^= $n2;
            $x ^= $x;
            $Ak ^= $Ak;
        }

        return Base64UrlSafe::encodeUnpadded($t . $n . $c);
    }


    /**
     * @param string $wrapped
     * @return KeyInterface
     *
     * @throws PaserkException
     */
    public function unwrapKey(string $wrapped): KeyInterface
    {
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
        } elseif (in_array($pieces[0], ['k2', 'k4'], true)) {
            $bytes = $this->unwrapKeyV2V4($header, $pieces[3]);
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
        $n = Binary::safeSubstr($decoded, 48, 32);
        $c = Binary::safeSubstr($decoded, 80);

        // Step 2:
        $Ak = Binary::safeSubstr(
            hash_hmac('sha384', "\x81" . $n, $this->wrappingKey->raw(), true),
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
            throw new PaserkException('Invalid authentication tag');
        }

        // Step 5:
        $x = hash_hmac('sha384', "\x80" . $n, $this->wrappingKey->raw(), true);
        $Ek = Binary::safeSubstr($x, 0, 32);
        $n2 = Binary::safeSubstr($x, 32, 16);

        // Step 6:
        $ptk = \openssl_decrypt(
            $c,
            'aes-256-ctr',
            $Ek,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $n2
        );

        // Wipe keys from memory after use:
        try {
            sodium_memzero($Ek);
            sodium_memzero($n2);
            sodium_memzero($x);
            sodium_memzero($Ak);
        } catch (\SodiumException $ex) {
            $Ek ^= $Ek;
            $n2 ^= $n2;
            $x ^= $x;
            $Ak ^= $Ak;
        }
        returN $ptk;
    }

    /**
     * @param string $header
     * @param string $encoded
     * @return string
     *
     * @throws PaserkException
     * @throws \SodiumException
     */
    protected function unwrapKeyV2V4(string $header, string $encoded): string
    {
        // Step 1:
        $decoded = Base64UrlSafe::decode($encoded);
        $t = Binary::safeSubstr($decoded,  0, 32);
        $n = Binary::safeSubstr($decoded, 32, 32);
        $c = Binary::safeSubstr($decoded, 64);

        // Step 2:
        $Ak = sodium_crypto_generichash("\x81" . $n, $this->wrappingKey->raw());

        // Step 3:
        $t2 = sodium_crypto_generichash($header . $n . $c, $Ak);

        // Step 4:
        if (!hash_equals($t2, $t)) {
            throw new PaserkException('Invalid authentication tag');
        }

        // Step 5:
        $x = sodium_crypto_generichash("\x80" . $n, $this->wrappingKey->raw(), 56);
        $Ek = Binary::safeSubstr($x, 0, 32);
        $n2 = Binary::safeSubstr($x, 32, 24);

        // Step 6:
        $ptk = sodium_crypto_stream_xchacha20_xor($c, $n2, $Ek);
        // Wipe keys from memory after use:
        try {
            sodium_memzero($Ek);
            sodium_memzero($n2);
            sodium_memzero($x);
            sodium_memzero($Ak);
        } catch (\SodiumException $ex) {
            $Ek ^= $Ek;
            $n2 ^= $n2;
            $x ^= $x;
            $Ak ^= $Ak;
        }
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
