<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\Key;

use Mdanter\Ecc\EccFactory;
use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE\EasyECC\ECDSA\{
    ConstantTimeMath,
    PublicKey,
    SecretKey
};
use ParagonIE\EasyECC\Exception\NotImplementedException;
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Util;
use Exception;
use SodiumException;
use TypeError;
use function
    hash_equals,
    sodium_crypto_sign_keypair,
    sodium_crypto_sign_publickey_from_secretkey,
    sodium_crypto_sign_secretkey;

/**
 * Class SealingSecretKey
 * @package ParagonIE\Paserk\Operations\Key
 */
class SealingSecretKey extends AsymmetricSecretKey
{
    /**
     * @param ProtocolInterface|null $protocol
     * @return self
     *
     * @throws Exception
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public static function generate(ProtocolInterface $protocol = null): AsymmetricSecretKey
    {
        $protocol = $protocol ?? new Version4;
        if (hash_equals($protocol::header(), Version3::HEADER)) {
            return new self(
                Util::dos2unix(SecretKey::generate(Version3::CURVE)->exportPem()),
                $protocol
            );
        }
        return new self(
            sodium_crypto_sign_secretkey(
                sodium_crypto_sign_keypair()
            ),
            $protocol
        );
    }

    /**
     * @param string $encoded
     * @param ProtocolInterface|null $version
     * @return self
     */
    public static function fromEncodedString(string $encoded, ProtocolInterface $version = null): self
    {
        if (!$version) {
            $version = new Version4();
        }
        if (hash_equals($version::header(), Version3::HEADER)) {
            return static::fromEncodedStringV3($encoded, $version);
        }
        return static::fromEncodedStringV4($encoded, $version);
    }

    /**
     * @param string $encoded
     * @param Version3 $version
     * @return self
     */
    public static function fromEncodedStringV3(string $encoded, Version3 $version): self
    {
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);

        if (Binary::safeStrlen($decoded) === 48) {
            return new self(
                (new SecretKey(
                    new ConstantTimeMath(),
                    EccFactory::getNistCurves()->generator384(null, true),
                    gmp_init(Hex::encode($decoded), 16)
                ))->exportPem()
            );
        }

        return new static($decoded, $version);
    }

    public static function fromEncodedStringV4(string $encoded, Version4 $version): self
    {
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);
        return new static($decoded, $version);
    }

    /**
     * @return AsymmetricSecretKey
     *
     * @throws Exception
     */
    public function toPasetoKey(): AsymmetricSecretKey
    {
        return new AsymmetricSecretKey(
            $this->key,
            $this->protocol
        );
    }

    /**
     * @return AsymmetricPublicKey
     *
     * @throws Exception
     * @throws TypeError
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        switch ($this->protocol::header()) {
            case Version3::HEADER:
                /** @var PublicKey $pk */
                $pk = SecretKey::importPem($this->key)->getPublicKey();
                return new SealingPublicKey(
                    $pk->exportPem(),
                    $this->protocol
                );
            default:
                return new SealingPublicKey(
                    sodium_crypto_sign_publickey_from_secretkey($this->key),
                    $this->protocol
                );
        }
    }
}
