<?php
declare(strict_types=1);

namespace ParagonIE\Paserk\Operations\PKE;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\ECDSA\PublicKey;
use ParagonIE\EasyECC\ECDSA\SecretKey;
use ParagonIE\Paserk\Operations\Key\SealingPublicKey;
use ParagonIE\Paserk\Operations\Key\SealingSecretKey;
use ParagonIE\Paserk\Operations\PKEInterface;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version3;

/**
 * Class PKEv3
 * @package ParagonIE\Paserk\Operations\PKE
 */
class PKEv3 implements PKEInterface
{
    /**
     * @return string
     */
    public static function header(): string
    {
        return 'k3.seal.';
    }

    /**
     * @link https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md#v3-encryption
     *
     * @param SymmetricKey $ptk
     * @param SealingPublicKey $pk
     * @return string
     * @throws \Exception
     */
    public function seal(SymmetricKey $ptk, SealingPublicKey $pk): string
    {
        $header = self::header();
        $easyECC = new EasyECC('P384');

        // Step 1:
        $eph_sk = SecretKey::generate('P384');
        /** @var PublicKey $eph_pk */
        $eph_pk = $eph_sk->getPublicKey();
        $seal_pk = PublicKey::importPem($pk->raw());

        $pk_compressed = $seal_pk->toString();
        $eph_pk_compressed = Hex::decode($eph_pk->toString());

        // Step 2:
        $xk = $easyECC->scalarmult($eph_sk, $seal_pk);

        // Step 3:
        $tmp = hash(
            'sha384',
            "\x01" . $header . $xk . $eph_pk_compressed . $pk_compressed,
            true
        );
        $Ek = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 16);

        // Step 4:
        $Ak = hash(
            'sha384',
            "\x01" . $header . $xk . $eph_pk_compressed . $pk_compressed,
            true
        );

        // Step 5:
        $edk = \openssl_encrypt(
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

        try {
            sodium_memzero($tmp);
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

        // Step 7:
        return Base64UrlSafe::encode($tag . $eph_pk_compressed . $edk);
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
     */
    public function unseal(string $header, string $encoded, SealingSecretKey $sk): SymmetricKey
    {
        if (!hash_equals($header, self::header())) {
            throw new PaserkException('Header mismatch');
        }
        $bin = Base64UrlSafe::decode($encoded);
        $tag = Binary::safeSubstr($bin, 0, 48);
        $eph_pk_compressed = Binary::safeSubstr($bin, 48, 49);
        $edk = Binary::safeSubstr($bin, 97);


        // Step 1:
        $easyECC = new EasyECC('P384');
        $seal_sk = SecretKey::importPem($sk->raw());
        $eph_pk = PublicKey::fromString(Hex::encode($eph_pk_compressed), 'P384');

        $xk = $easyECC->scalarmult($seal_sk, $eph_pk);
        $pk_compressed = $seal_sk->getPublicKey()->toString();

        // Step 2:
        $Ak = hash(
            'sha384',
            "\x01" . $header . $xk . $eph_pk_compressed . $pk_compressed,
            true
        );

        // Step 3:
        $t2 = hash_hmac(
            'sha384',
            $header . $eph_pk_compressed . $edk,
            $Ak,
            true
        );

        // Step 4:
        if (!hash_equals($t2, $tag)) {
            throw new PaserkException('Invalid auth tag');
        }

        // Step 5:
        $tmp = hash(
            'sha384',
            "\x01" . $header . $xk . $eph_pk_compressed . $pk_compressed,
            true
        );
        $Ek = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 16);

        // Step 6:
        $ptk = openssl_encrypt(
            $edk,
            'aes-256-ctr',
            $Ek,
            OPENSSL_NO_PADDING | OPENSSL_RAW_DATA,
            $nonce
        );

        try {
            sodium_memzero($tmp);
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

        // Step 7:
        return new SymmetricKey($ptk, new Version3());
    }
}
