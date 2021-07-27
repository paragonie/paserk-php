<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PKE;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paserk\Operations\Key\SealingPublicKey;
use ParagonIE\Paserk\Operations\Key\SealingSecretKey;
use ParagonIE\Paserk\Operations\PKEInterface;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\SymmetricKey;

/**
 * Class PKEv2v4
 * @package ParagonIE\Paserk\Operations\PKE
 */
class PKEv2 implements PKEInterface
{
    /**
     * @return string
     */
    public static function header(): string
    {
        return 'k2.seal.';
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v2v4-encryption
     *
     * @param SymmetricKey $ptk
     * @param SealingPublicKey $pk
     * @return string
     * @throws \SodiumException
     */
    public function seal(SymmetricKey $ptk, SealingPublicKey $pk): string
    {
        $header = static::header();

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
            "\x01" . $header . $xk . $eph_pk . $xpk
        );
        $Ak = sodium_crypto_generichash(
            "\x02" . $header . $xk . $eph_pk . $xpk
        );
        $nonce = sodium_crypto_generichash($eph_pk . $xpk, '', 24);

        $edk = sodium_crypto_stream_xchacha20_xor(
            $ptk->raw(),
            $nonce,
            $Ek
        );
        $tag = sodium_crypto_generichash($header . $eph_pk . $edk, $Ak);
        try {
            sodium_memzero($Ek);
            sodium_memzero($nonce);
            sodium_memzero($xk);
            sodium_memzero($Ak);
        } catch (\SodiumException $ex) {
            $Ek ^= $Ek;
            $nonce ^= $nonce;
            $xk ^= $xk;
            $Ak ^= $Ak;
        }
        return Base64UrlSafe::encode($tag . $eph_pk . $edk);
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v2v4-decryption
     *
     * @param string $header
     * @param string $encoded
     * @param SealingSecretKey $sk
     * @return SymmetricKey
     */
    public function unseal(string $header, string $encoded, SealingSecretKey $sk): SymmetricKey
    {
        if (!hash_equals($header, static::header())) {
            throw new PaserkException('Header mismatch');
        }
        $bin = Base64UrlSafe::decode($encoded);
        $tag = Binary::safeSubstr($bin, 0, 32);
        $eph_pk = Binary::safeSubstr($bin, 32, 32);
        $edk = Binary::safeSubstr($bin, 64, 32);

        // Step 1:
        $xsk = sodium_crypto_sign_ed25519_sk_to_curve25519($sk->raw());
        $xpk = sodium_crypto_sign_ed25519_pk_to_curve25519($sk->getPublicKey()->raw());

        // Step 2:
        $xk = sodium_crypto_scalarmult($xsk, $eph_pk);

        // Step 3:
        $Ak = sodium_crypto_generichash(
            "\x02" . $header . $xk . $eph_pk . $xpk
        );

        // Step 4:
        $t2 = sodium_crypto_generichash($header . $eph_pk . $edk, $Ak);

        // Step 5:
        if (!hash_equals($t2, $tag)) {
            throw new PaserkException('Invalid auth tag');
        }

        // Step 6:
        $Ek = sodium_crypto_generichash(
            "\x01" . $header . $xk . $eph_pk . $xpk
        );
        // Step 7:
        $nonce = sodium_crypto_generichash($eph_pk . $xpk, '', 24);

        $ptk = sodium_crypto_stream_xchacha20_xor(
            $edk,
            $nonce,
            $Ek
        );
        try {
            sodium_memzero($Ek);
            sodium_memzero($nonce);
            sodium_memzero($xk);
            sodium_memzero($xsk);
            sodium_memzero($Ak);
        } catch (\SodiumException $ex) {
            $Ek ^= $Ek;
            $nonce ^= $nonce;
            $xk ^= $xk;
            $xsk ^= $xsk;
            $Ak ^= $Ak;
        }
        return new SymmetricKey($ptk, $sk->getProtocol());
    }
}
