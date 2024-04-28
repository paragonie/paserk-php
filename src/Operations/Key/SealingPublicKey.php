<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\Key;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE\EasyECC\Exception\InvalidPublicKeyException;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use Exception;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use TypeError;

/**
 * Class SealingPublicKey
 * @package ParagonIE\Paserk\Operations\Key
 */
class SealingPublicKey extends AsymmetricPublicKey
{
    /**
     * @return AsymmetricPublicKey
     *
     * @throws PaserkException
     * @throws Exception
     */
    public function toPasetoKey(): AsymmetricPublicKey
    {
        return new AsymmetricPublicKey(
            $this->key,
            $this->protocol
        );
    }

    /**
     * Initialize a public key from a base64url-encoded string.
     *
     * @param string $encoded
     * @param ProtocolInterface|null $version
     * @return self
     *
     * @throws Exception
     * @throws TypeError
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
     * @throws InvalidPublicKeyException
     */
    public static function fromEncodedStringV3(string $encoded, Version3 $version): self
    {
        $decodeString = Base64UrlSafe::decode($encoded);
        $length = Binary::safeStrlen($encoded);
        if ($length === 98) {
            $decoded = Version3::getPublicKeyPem($decodeString);
        } elseif ($length === 49) {
            $decoded = Version3::getPublicKeyPem(Hex::encode($decodeString));
        } else {
            $decoded = $decodeString;
        }

        return new static($decoded, $version);
    }

    /**
     * @param string $encoded
     * @param Version4 $version
     * @return self
     * @throws Exception
     */
    public static function fromEncodedStringV4(string $encoded, Version4 $version): self
    {
        $decoded = Base64UrlSafe::decode($encoded);
        return new static($decoded, $version);
    }
}
