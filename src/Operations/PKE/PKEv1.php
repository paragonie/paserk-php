<?php
declare(strict_types=1);

namespace ParagonIE\Paserk\Operations\PKE;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paserk\Operations\Key\{
    SealingPublicKey,
    SealingSecretKey
};
use ParagonIE\Paserk\Operations\{
    PKE,
    PKEInterface
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\{
    Keys\SymmetricKey,
    Protocol\Version1,
    ProtocolInterface
};
use phpseclib\Crypt\RSA;
use Exception;
use function
    hash,
    hash_equals,
    hash_hmac,
    openssl_decrypt,
    openssl_encrypt,
    pack,
    random_bytes,
    unpack;

/**
 * Class PKEv1
 * @package ParagonIE\Paserk\Operations\PKE
 */
class PKEv1 implements PKEInterface
{
    use PKETrait;

    /**
     * @return string
     */
    public static function header(): string
    {
        return 'k1.seal.';
    }

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface
    {
        return new Version1();
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v1-encryption
     *
     * @param SymmetricKey $ptk
     * @param SealingPublicKey $pk
     * @return string
     * @throws Exception
     */
    public function seal(SymmetricKey $ptk, SealingPublicKey $pk): string
    {
        $rsa = Version1::getRsa();
        $rsa->loadKey($pk->raw());
        $bitLength = Binary::safeStrlen($rsa->modulus->toBits());
        if ($bitLength !== 4096) {
            throw new PaserkException('Public key modulus must be 4096 bits in size');
        }
        /// @SPEC DETAIL: n > 2^4095 and n < (2^4096 + 1)
        $exp = (int) $rsa->exponent->toString();
        if ($exp !== 65537) {
            throw new PaserkException('Public key exponent must be 65537');
        }
        /// @SPEC DETAIL: e == 65537

        // We're using RSA-KEM, which means we work with unpadded RSA
        $rsa->setEncryptionMode(RSA::ENCRYPTION_NONE);

        // Step 1:
        // Generate a 4096-bit random integer, with clamping bits to ensure r < pk.n
        $r = random_bytes(512);
        $r0 = unpack('C', $r[0])[1];
        $r[0] = pack('C', ($r0 | 0x40) & 0x7f);

        // Step 2:
        $c = $rsa->encrypt($r);

        // Step 3:
        $x = hash_hmac(
            'sha384',
            PKE::DOMAIN_SEPARATION_ENCRYPT . self::header() . $r,
            hash('sha384', $c, true),
            true
        );
        /// @SPEC DETAIL: Prefix must be 0x01 for encryption keys

        $Ek = Binary::safeSubstr($x, 0, 32);
        $nonce = Binary::safeSubstr($x, 32, 16);

        // Step 4:
        $Ak = hash_hmac(
            'sha384',
            PKE::DOMAIN_SEPARATION_AUTH . self::header() . $r,
            hash('sha384', $c, true),
            true
        );
        /// @SPEC DETAIL: Prefix must be 0x02 for authentication keys

        // Step 5:
        $edk = openssl_encrypt(
            $ptk->raw(),
            'aes-256-ctr',
            $Ek,
            OPENSSL_NO_PADDING | OPENSSL_RAW_DATA,
            $nonce
        );

        $t = hash_hmac('sha384', self::header() . $c . $edk, $Ak, true);
        /// @SPEC DETAIL: header || c || edk, in that order

        Util::wipe($Ek);
        Util::wipe($nonce);
        Util::wipe($x);
        Util::wipe($Ak);
        return Base64UrlSafe::encodeUnpadded($t . $edk . $c);
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v1-decryption
     *
     * @param string $header
     * @param string $encoded
     * @param SealingSecretKey $sk
     * @return SymmetricKey
     *
     * @throws PaserkException
     */
    public function unseal(string $header, string $encoded, SealingSecretKey $sk): SymmetricKey
    {
        $bin = Base64UrlSafe::decode($encoded);
        $tag = Binary::safeSubstr($bin, 0, 48);
        $edk = Binary::safeSubstr($bin, 48, 32);
        $c = Binary::safeSubstr($bin, 80);

        // Step 1:
        if (!hash_equals($header, self::header())) {
            throw new PaserkException('Header mismatch');
        }
        $rsa = Version1::getRsa();
        $rsa->loadKey($sk->raw());
        $rsa->setEncryptionMode(RSA::ENCRYPTION_NONE);

        $bitLength = Binary::safeStrlen($rsa->modulus->toBits());
        if ($bitLength !== 4096) {
            throw new PaserkException('Public key modulus must be 4096 bits in size');
        }
        /// @SPEC DETAIL: n > 2^4095 and n < (2^4096 + 1)
        $exp = (int) $rsa->publicExponent->toString();
        if ($exp !== 65537) {
            throw new PaserkException('Public key exponent must be 65537');
        }
        /// @SPEC DETAIL: e == 65537

        // Step 2:
        $r = $rsa->decrypt($c);

        // Step 3:
        $Ak = hash_hmac(
            'sha384',
            PKE::DOMAIN_SEPARATION_AUTH . self::header() . $r,
            hash('sha384', $c, true),
            true
        );
        /// @SPEC DETAIL: Prefix must be 0x02 for authentication keys

        // Step 4:
        $t2 = hash_hmac('sha384', self::header() . $c . $edk, $Ak, true);

        // Step 5:
        if (!hash_equals($t2, $tag)) {
            Util::wipe($t2);
            Util::wipe($Ak);
            throw new PaserkException('Invalid auth tag');
        }
        /// @SPEC DETAIL: This must be a constant-time compare.

        // Step 6:
        $x = hash_hmac(
            'sha384',
            PKE::DOMAIN_SEPARATION_ENCRYPT . self::header() . $r,
            hash('sha384', $c, true),
            true
        );
        /// @SPEC DETAIL: Prefix must be 0x01 for encryption keys
        $Ek = Binary::safeSubstr($x, 0, 32);
        $nonce = Binary::safeSubstr($x, 32, 16);

        // Step 7:
        $ptk = openssl_decrypt(
            $edk,
            'aes-256-ctr',
            $Ek,
            OPENSSL_NO_PADDING | OPENSSL_RAW_DATA,
            $nonce
        );
        Util::wipe($Ek);
        Util::wipe($nonce);
        Util::wipe($x);
        Util::wipe($Ak);
        Util::wipe($t2);

        // Step 8:
        return new SymmetricKey($ptk, new Version1());
    }
}
