<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PKE;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE\EasyECC\{
    EasyECC,
    ECDSA\PublicKey,
    ECDSA\SecretKey
};
use ParagonIE\Paseto\{
    ProtocolInterface,
    Keys\SymmetricKey,
    Protocol\Version3
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
use Exception;
use TypeError;
use function
    hash,
    hash_equals,
    hash_hmac,
    openssl_decrypt,
    openssl_encrypt;

/**
 * Class PKEv3
 * @package ParagonIE\Paserk\Operations\PKE
 */
class PKEv3 implements PKEInterface
{
    use PKETrait;

    /**
     * @return string
     */
    public static function header(): string
    {
        return 'k3.seal.';
    }

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface
    {
        return new Version3();
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v3-encryption
     *
     * @param SymmetricKey $ptk
     * @param SealingPublicKey $pk
     * @return string
     *
     * @throws Exception
     */
    public function seal(SymmetricKey $ptk, SealingPublicKey $pk): string
    {
        $header = self::header();
        $easyECC = new EasyECC('P384');

        // Step 1:
        $this->assertKeyVersion($pk);
        $eph_sk = SecretKey::generate('P384');
        /** @var PublicKey $eph_pk */
        $eph_pk = $eph_sk->getPublicKey();
        $seal_pk = PublicKey::importPem($pk->raw());

        $pk_compressed = Hex::decode($seal_pk->toString());
        $eph_pk_compressed = Hex::decode($eph_pk->toString());

        // Step 2:
        $xk = $easyECC->scalarmult($eph_sk, $seal_pk);

        // Step 3:
        $tmp = hash(
            'sha384',
            PKE::DOMAIN_SEPARATION_ENCRYPT . $header . $xk . $eph_pk_compressed . $pk_compressed,
            true
        );
        /// @SPEC DETAIL: Prefix must be 0x01 for encryption keys
        $Ek = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 16);

        // Step 4:
        $Ak = hash(
            'sha384',
            PKE::DOMAIN_SEPARATION_AUTH . $header . $xk . $eph_pk_compressed . $pk_compressed,
            true
        );
        /// @SPEC DETAIL: Prefix must be 0x02 for authentication keys

        // Step 5:
        $edk = openssl_encrypt(
            $ptk->raw(),
            'aes-256-ctr',
            $Ek,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $nonce
        );

        // Step 6:
        $tag = hash_hmac(
            'sha384',
            $header . $eph_pk_compressed . $edk,
            $Ak,
            true
        );
        /// @SPEC DETAIL: h || epk || edk

        Util::wipe($tmp);
        Util::wipe($Ek);
        Util::wipe($nonce);
        Util::wipe($xk);
        Util::wipe($Ak);

        // Step 7:
        return Base64UrlSafe::encodeUnpadded($tag . $eph_pk_compressed . $edk);
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v3-decryption
     *
     * @param string $header
     * @param string $encoded
     * @param SealingSecretKey $sk
     * @return SymmetricKey
     *
     * @throws PaserkException
     * @throws Exception
     */
    public function unseal(string $header, string $encoded, SealingSecretKey $sk): SymmetricKey
    {
        if (!hash_equals($header, self::header())) {
            throw new PaserkException('Header mismatch');
        }
        $this->assertKeyVersion($sk);

        $bin = Base64UrlSafe::decode($encoded);
        $tag = Binary::safeSubstr($bin, 0, 48);
        $eph_pk_compressed = Binary::safeSubstr($bin, 48, 49);
        $edk = Binary::safeSubstr($bin, 97);

        // Step 1:
        $easyECC = new EasyECC('P384');
        $seal_sk = SecretKey::importPem($sk->raw());
        $eph_pk = PublicKey::fromString(Hex::encode($eph_pk_compressed), 'P384');

        $xk = $easyECC->scalarmult($seal_sk, $eph_pk);

        /** @var PublicKey $pk_obj */
        $pk_obj = $seal_sk->getPublicKey();
        if (!($pk_obj instanceof PublicKey)) {
            throw new TypeError("An unexpected type violation occurred");
        }
        $pk_compressed = Hex::decode($pk_obj->toString());

        // Step 2:
        $Ak = hash(
            'sha384',
            PKE::DOMAIN_SEPARATION_AUTH . $header . $xk . $eph_pk_compressed . $pk_compressed,
            true
        );
        /// @SPEC DETAIL: Prefix must be 0x02 for authentication keys

        // Step 3:
        $t2 = hash_hmac(
            'sha384',
            $header . $eph_pk_compressed . $edk,
            $Ak,
            true
        );
        /// @SPEC DETAIL: h || epk || edk

        // Step 4:
        if (!hash_equals($t2, $tag)) {
            Util::wipe($t2);
            Util::wipe($Ak);
            throw new PaserkException('Invalid auth tag');
        }
        /// @SPEC DETAIL: This must be a constant-time compare.

        // Step 5:
        $tmp = hash(
            'sha384',
            PKE::DOMAIN_SEPARATION_ENCRYPT . $header . $xk . $eph_pk_compressed . $pk_compressed,
            true
        );
        /// @SPEC DETAIL: Prefix must be 0x01 for encryption keys
        $Ek = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 16);

        // Step 6:
        $ptk = openssl_decrypt(
            $edk,
            'aes-256-ctr',
            $Ek,
            OPENSSL_NO_PADDING | OPENSSL_RAW_DATA,
            $nonce
        );

        Util::wipe($tmp);
        Util::wipe($Ek);
        Util::wipe($nonce);
        Util::wipe($xk);
        Util::wipe($Ak);
        Util::wipe($t2);

        // Step 7:
        return new SymmetricKey($ptk, new Version3());
    }
}
