<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PBKW;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Util;
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
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\ProtocolInterface;
use Exception;
use TypeError;
use function
    hash,
    hash_equals,
    hash_hmac,
    hash_pbkdf2,
    openssl_decrypt,
    openssl_encrypt,
    pack,
    random_bytes,
    unpack;

/**
 * Class PBKWv3
 * @package ParagonIE\Paserk\Operations\PBKW
 */
class PBKWv3 implements PBKWInterface
{
    /**
     * @return string
     */
    public static function localHeader(): string
    {
        return 'k3.local-pw.';
    }

    /**
     * @return string
     */
    public static function secretHeader(): string
    {
        return 'k3.secret-pw.';
    }

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface
    {
        return new Version3();
    }

    /**
     * @param KeyInterface $key
     * @param HiddenString $password
     * @param array $options
     * @return string
     *
     * @throws Exception
     * @throws PaserkException
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

        // Step 1:
        $salt = random_bytes(32);
        $iterations = $options['iterations'] ?? 100000;
        $iterPack = pack('N', $iterations);

        // Step 2:
        $preKey = hash_pbkdf2('sha384', $password->getString(), $salt, $iterations, 32, true);

        // Step 3:
        $Ek = Binary::safeSubstr(
            hash(
                'sha384',
                PBKW::DOMAIN_SEPARATION_ENCRYPT . $preKey,
                true
            ),
            0,
            32
        );
        /// @SPEC DETAIL: Must be prefixed with 0xFF

        // Step 4:
        $Ak = hash('sha384', PBKW::DOMAIN_SEPARATION_AUTH . $preKey, true);
        /// @SPEC DETAIL:              ^ Must be prefixed with 0xFE

        // Step 5:
        $nonce = random_bytes(16);

        // Step 6:
        $edk = openssl_encrypt(
            $key->raw(),
            'aes-256-ctr',
            $Ek,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $nonce
        );

        // Step 7:
        $tag = hash_hmac(
            'sha384',
            $header . $salt . $iterPack . $nonce . $edk,
            $Ak,
            true
        );

        // Step 8:
        return Base64UrlSafe::encodeUnpadded(
            $salt .
            $iterPack .
            $nonce .
            $edk .
            $tag
        );
    }

    /**
     * @param string $header
     * @param string $wrapped
     * @param HiddenString $password
     * @return KeyInterface
     * @throws \Exception
     */
    public function unwrapWithPassword(
        string $header,
        string $wrapped,
        HiddenString $password
    ): KeyInterface {
        $decoded = Base64UrlSafe::decode($wrapped);
        $decodedLen = Binary::safeStrlen($decoded);

        // Split into components
        $salt = Binary::safeSubstr($decoded, 0, 32);
        $iterPack = Binary::safeSubstr($decoded, 32, 4);
        $nonce = Binary::safeSubstr($decoded, 36, 16);
        $edk = Binary::safeSubstr($decoded, 52, $decodedLen - 100);
        $tag = Binary::safeSubstr($decoded, $decodedLen - 48, 48);

        $iterations = unpack('N', $iterPack)[1];

        // Step 2:
        $preKey = hash_pbkdf2('sha384', $password->getString(), $salt, $iterations, 32, true);

        // Step 3:
        $Ak = hash('sha384', PBKW::DOMAIN_SEPARATION_AUTH . $preKey, true);
        /// @SPEC DETAIL:              ^ Must be prefixed with 0xFE

        // Step 4:
        $t2 = hash_hmac(
            'sha384',
            $header . $salt . $iterPack . $nonce . $edk,
            $Ak,
            true
        );

        // Step 5:
        if (!hash_equals($t2, $tag)) {
            Util::wipe($t2);
            Util::wipe($Ak);
            throw new PaserkException('Invalid password or wrapped key');
        }
        /// @SPEC DETAIL: This check must be constant-time.

        // Step 6:
        $Ek = Binary::safeSubstr(
            hash('sha384', PBKW::DOMAIN_SEPARATION_ENCRYPT . $preKey, true),
            0,
            32
        );
        /// @SPEC DETAIL: Must be prefixed with 0xFF

        // Step 7:
        $ptk = openssl_decrypt(
            $edk,
            'aes-256-ctr',
            $Ek,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $nonce
        );

        // Step 8:
        if (hash_equals($header, static::localHeader())) {
            return new SymmetricKey($ptk, static::getProtocol());
        }
        if (hash_equals($header, static::secretHeader())) {
            return new AsymmetricSecretKey($ptk, static::getProtocol());
        }
        throw new TypeError();
    }
}
