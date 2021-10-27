<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PBKW;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Operations\{
    PBKW,
    PBKWInterface
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\ProtocolInterface;
use Exception;
use SodiumException;
use TypeError;
use function
    hash_equals,
    sodium_crypto_generichash,
    sodium_crypto_pwhash,
    sodium_crypto_stream_xchacha20_xor,
    pack,
    random_bytes,
    unpack;

/**
 * Class PBKWv2
 * @package ParagonIE\Paserk\Operations\PBKW
 */
class PBKWv2 implements PBKWInterface
{
    /**
     * @return string
     */
    public static function localHeader(): string
    {
        return 'k2.local-pw.';
    }

    /**
     * @return string
     */
    public static function secretHeader(): string
    {
        return 'k2.secret-pw.';
    }

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface
    {
        return new Version2();
    }

    /**
     * @param KeyInterface $key
     * @param HiddenString $password
     * @param array $options
     * @return string
     *
     * @throws Exception
     * @throws PaserkException
     * @throws SodiumException
     */
    public function wrapWithPassword(
        KeyInterface $key,
        HiddenString $password,
        array $options = []
    ): string {
        if ($key instanceof SymmetricKey) {
            $header = static::localHeader();
        } elseif ($key instanceof AsymmetricSecretKey) {
            $header = static::secretHeader();
        } else {
            throw new PaserkException('Invalid key type');
        }

        $ops = $options['opslimit'] ?? SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
        $mem = $options['memlimit'] ?? SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
        $memPack = pack('J', $mem);
        $opsPack = pack('N', $ops);
        $paraPack = "\x00\x00\x00\x01"; // We can't set this in PHP

        // Step 1:
        $salt = random_bytes(16);

        // Step 2:
        $preKey = sodium_crypto_pwhash(
            32,
            $password->getString(),
            $salt,
            $ops,
            $mem,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );

        // Step 3:
        $Ek = sodium_crypto_generichash(PBKW::DOMAIN_SEPARATION_ENCRYPT . $preKey);
        /// @SPEC DETAIL:                ^ Must be prefixed with 0xFF for encryption

        // Step 4:
        $Ak = sodium_crypto_generichash(PBKW::DOMAIN_SEPARATION_AUTH . $preKey);
        /// @SPEC DETAIL:                ^ Must be prefixed with 0xFE for authentication

        // Step 5:
        $nonce = random_bytes(24);

        // Step 6:
        $edk = sodium_crypto_stream_xchacha20_xor(
            $key->raw(),
            $nonce,
            $Ek
        );

        // Step 7:
        $tag = sodium_crypto_generichash(
            $header . $salt . $memPack . $opsPack . $paraPack . $nonce . $edk,
            $Ak
        );

        return Base64UrlSafe::encodeUnpadded(
            $salt . $memPack . $opsPack . $paraPack . $nonce . $edk . $tag
        );
    }

    /**
     * @param string $header
     * @param string $wrapped
     * @param HiddenString $password
     * @return KeyInterface
     *
     * @throws Exception
     * @throws PaserkException
     * @throws SodiumException
     * @throws TypeError
     */
    public function unwrapWithPassword(
        string $header,
        string $wrapped,
        HiddenString $password
    ): KeyInterface {
        $decoded = Base64UrlSafe::decode($wrapped);
        $decodedLen = Binary::safeStrlen($decoded);

        $salt = Binary::safeSubstr($decoded, 0, 16);
        $memPack = Binary::safeSubstr($decoded, 16, 8);
        $opsPack = Binary::safeSubstr($decoded, 24, 4);
        $paraPack = Binary::safeSubstr($decoded, 28, 4);
        $nonce = Binary::safeSubstr($decoded, 32, 24);
        $edk = Binary::safeSubstr($decoded, 56, $decodedLen - 88);
        $tag = Binary::safeSubstr($decoded, $decodedLen - 32, 32);
        $mem = unpack('J', $memPack)[1];
        $ops = unpack('N', $opsPack)[1];
        // Parallelism is not used in PHP, but we still store it as p=1
        if (!hash_equals($paraPack, "\x00\x00\x00\x01")) {
            // Fail fast if an invalid parameter is provided
            throw new PaserkException("Parallelism > 1 is not supported in PHP");
        }

        // Step 1:
        $preKey = sodium_crypto_pwhash(
            32,
            $password->getString(),
            $salt,
            $ops,
            $mem,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );

        // Step 2:
        $Ak = sodium_crypto_generichash(PBKW::DOMAIN_SEPARATION_AUTH . $preKey);
        /// @SPEC DETAIL:                ^ Must be prefixed with 0xFE for authentication

        // Step 3:
        $t2 = sodium_crypto_generichash(
            $header . $salt . $memPack . $opsPack . $paraPack . $nonce . $edk,
            $Ak
        );

        // Step 4:
        if (!hash_equals($t2, $tag)) {
            throw new PaserkException('Invalid password or wrapped key');
        }

        // Step 5:
        $Ek = sodium_crypto_generichash(PBKW::DOMAIN_SEPARATION_ENCRYPT . $preKey);
        /// @SPEC DETAIL:                ^ Must be prefixed with 0xFF for encryption

        // Step 6:
        $ptk = sodium_crypto_stream_xchacha20_xor(
            $edk,
            $nonce,
            $Ek
        );

        if (hash_equals($header, static::localHeader())) {
            return new SymmetricKey($ptk, static::getProtocol());
        }
        if (hash_equals($header, static::secretHeader())) {
            return new AsymmetricSecretKey($ptk, static::getProtocol());
        }
        throw new TypeError();
    }
}
