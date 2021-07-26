<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\PaserkTypeInterface;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\Protocol\Version1;

/**
 * Class SecretType
 * @package ParagonIE\Paserk\Types
 */
class SecretType implements PaserkTypeInterface
{
    /**
     * @param string $paserk
     * @return KeyInterface
     *
     * @throws PaserkException
     */
    public function decode(string $paserk): KeyInterface
    {
        $pieces = explode('.', $paserk);
        if (count($pieces) !== 3) {
            throw new PaserkException('Invalid PASERK');
        }
        if (!hash_equals(self::getTypeLabel(), $pieces[1])) {
            throw new PaserkException('Invalid PASERK');
        }
        if ($pieces[0] === 'k1') {
            return $this->decodeV1($pieces[2]);
        }
        return new AsymmetricSecretKey(
            Base64UrlSafe::decode($pieces[2]),
            Util::getPasetoVersion($pieces[0])
        );
    }

    /**
     * @param string $encoded
     * @return AsymmetricSecretKey
     * @throws \Exception
     */
    public function decodeV1(string $encoded): AsymmetricSecretKey
    {
        $raw = Base64UrlSafe::decode($encoded);
        $b64 = Base64::encode($raw);
        $pem = '-----BEGIN RSA PRIVATE KEY-----' . "\n" .
            chunk_split($b64, 64, "\n") .
            '-----END RSA PRIVATE KEY-----';
        return new AsymmetricSecretKey($pem, new Version1());
    }

    /**
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof AsymmetricSecretKey)) {
            throw new PaserkException('Only symmetric keys can be serialized as kx.local.');
        }
        $version = Util::getPaserkHeader($key->getProtocol());
        switch ($version) {
            case 'k1':
                return implode('.', [
                    $version,
                    self::getTypeLabel(),
                    $this->encodeV1($key->raw())
                ]);
            case 'k2':
            case 'k3':
            case 'k4':
                return implode('.', [
                    $version,
                    self::getTypeLabel(),
                    $key->encode()
                ]);
            default:
                throw new PaserkException('Unknown version');
        }
    }

    /**
     * @param string $pk
     * @return string
     */
    public function encodeV1(string $pk): string
    {
        $pem = preg_replace('#-{3,}(BEGIN|END) [^-]+-{3,}#', '', $pk);
        $decoded = Base64::decode(preg_replace('#[^A-Za-z0-9+/]#', '', $pem));
        return Base64UrlSafe::encodeUnpadded($decoded);
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'secret';
    }

    /**
     * Get the lid PASERK for the PASERK representation of this local key.
     *
     * @param KeyInterface $key
     * @return string
     * @throws PaserkException
     * @throws \SodiumException
     */
    public function id(KeyInterface $key): string
    {
        return Pid::encode(
            $key->getProtocol(),
            $this->encode($key)
        );
    }
}
