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
    Protocol\Version2,
    ProtocolInterface
};
use SodiumException;
use function
    hash_equals,
    sodium_crypto_box_keypair,
    sodium_crypto_box_publickey,
    sodium_crypto_box_secretkey,
    sodium_crypto_generichash,
    sodium_crypto_scalarmult,
    sodium_crypto_sign_ed25519_sk_to_curve25519,
    sodium_crypto_sign_ed25519_pk_to_curve25519,
    sodium_crypto_stream_xchacha20_xor;

/**
 * Class PKEv2v4
 * @package ParagonIE\Paserk\Operations\PKE
 */
class PKEv2 implements PKEInterface
{
    use PKETrait;

    /**
     * @return string
     */
    public static function header(): string
    {
        return 'k2.seal.';
    }

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface
    {
        return new Version2();
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v2v4-encryption
     *
     * @param SymmetricKey $ptk
     * @param SealingPublicKey $pk
     * @return string
     *
     * @throws PaserkException
     * @throws SodiumException
     */
    public function seal(SymmetricKey $ptk, SealingPublicKey $pk): string
    {
        $header = static::header();
        $this->assertKeyVersion($pk);

        // Step 1:
        $xpk = sodium_crypto_sign_ed25519_pk_to_curve25519($pk->raw());

        // Step 2:
        $eph_kp = sodium_crypto_box_keypair();
        $eph_sk = sodium_crypto_box_secretkey($eph_kp);
        $eph_pk = sodium_crypto_box_publickey($eph_kp);

        // Step 3:
        $xk = sodium_crypto_scalarmult($eph_sk, $xpk);

        // Step 4:
        $Ek = sodium_crypto_generichash(
            PKE::DOMAIN_SEPARATION_ENCRYPT . $header . $xk . $eph_pk . $xpk
        );
        /// @SPEC DETAIL: Prefix is 0x01 for encryption keys
        $Ak = sodium_crypto_generichash(
            PKE::DOMAIN_SEPARATION_AUTH . $header . $xk . $eph_pk . $xpk
        );
        /// @SPEC DETAIL: Prefix is 0x02 for authentication keys
        $nonce = sodium_crypto_generichash($eph_pk . $xpk, '', 24);

        $edk = sodium_crypto_stream_xchacha20_xor(
            $ptk->raw(),
            $nonce,
            $Ek
        );
        $tag = sodium_crypto_generichash($header . $eph_pk . $edk, $Ak);
        /// @SPEC DETAIL: h || epk || edk, in that order
        Util::wipe($Ek);
        Util::wipe($nonce);
        Util::wipe($xk);
        Util::wipe($Ak);
        return Base64UrlSafe::encodeUnpadded($tag . $eph_pk . $edk);
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v2v4-decryption
     *
     * @param string $header
     * @param string $encoded
     * @param SealingSecretKey $sk
     * @return SymmetricKey
     *
     * @throws PaserkException
     * @throws SodiumException
     */
    public function unseal(string $header, string $encoded, SealingSecretKey $sk): SymmetricKey
    {
        $bin = Base64UrlSafe::decode($encoded);
        $tag = Binary::safeSubstr($bin, 0, 32);
        $eph_pk = Binary::safeSubstr($bin, 32, 32);
        $edk = Binary::safeSubstr($bin, 64, 32);

        // Step 1:
        if (!hash_equals($header, static::header())) {
            throw new PaserkException('Header mismatch');
        }
        $this->assertKeyVersion($sk);

        // Step 2:
        $xsk = sodium_crypto_sign_ed25519_sk_to_curve25519($sk->raw());
        $xpk = sodium_crypto_sign_ed25519_pk_to_curve25519($sk->getPublicKey()->raw());

        // Step 3:
        $xk = sodium_crypto_scalarmult($xsk, $eph_pk);

        // Step 4:
        $Ak = sodium_crypto_generichash(
            PKE::DOMAIN_SEPARATION_AUTH . $header . $xk . $eph_pk . $xpk
        );
        /// @SPEC DETAIL: Prefix is 0x02 for authentication keys

        // Step 5:
        $t2 = sodium_crypto_generichash($header . $eph_pk . $edk, $Ak);
        /// @SPEC DETAIL: h || epk || edk

        // Step 6:
        if (!hash_equals($t2, $tag)) {
            Util::wipe($t2);
            Util::wipe($Ak);
            throw new PaserkException('Invalid auth tag');
        }
        /// @SPEC DETAIL: This must be a constant-time compare.

        // Step 7:
        $Ek = sodium_crypto_generichash(
            PKE::DOMAIN_SEPARATION_ENCRYPT . $header . $xk . $eph_pk . $xpk
        );
        /// @SPEC DETAIL: Prefix is 0x01 for encryption keys

        // Step 8:
        $nonce = sodium_crypto_generichash($eph_pk . $xpk, '', 24);

        // Step 9:
        $ptk = sodium_crypto_stream_xchacha20_xor(
            $edk,
            $nonce,
            $Ek
        );
        Util::wipe($Ek);
        Util::wipe($nonce);
        Util::wipe($xk);
        Util::wipe($xsk);
        Util::wipe($Ak);

        // Step 10:
        return new SymmetricKey($ptk, $sk->getProtocol());
    }
}
