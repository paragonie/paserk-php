<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\ConstantTime\{Base64, Base64UrlSafe, Binary};
use ParagonIE\Paserk\ConstraintTrait;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\PaserkTypeInterface;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\Protocol\Version1;
use Exception;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\ProtocolInterface;
use function
    chunk_split,
    count,
    explode,
    hash_equals,
    implode,
    preg_replace;

/**
 * Class SecretType
 * @package ParagonIE\Paserk\Types
 */
class SecretType implements PaserkTypeInterface
{
    use ConstraintTrait;

    public function __construct(ProtocolInterface ...$versions) {
        if (count($versions) > 0) {
            $this->collection = new ProtocolCollection(...$versions);
        } else {
            $this->collection = ProtocolCollection::default();
        }
    }

    /**
     * @param string $paserk
     * @return KeyInterface
     *
     * @throws Exception
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
        $version = Util::getPasetoVersion($pieces[0]);
        $this->throwIfInvalidProtocol($version);
        /// @SPEC DETAIL: Algorithm Lucidity

        if ($pieces[0] === 'k1') {
            return $this->decodeV1($pieces[2]);
        }
        $rawKey = Base64UrlSafe::decode($pieces[2]);
        $this->throwIfWrongKeyLength($version, Binary::safeStrlen($rawKey));
        return new AsymmetricSecretKey($rawKey, $version);
    }

    /**
     * @param string $encoded
     * @return AsymmetricSecretKey
     * @throws \Exception
     */
    public function decodeV1(string $encoded): AsymmetricSecretKey
    {
        $raw = Base64UrlSafe::decode($encoded);
        $length = Binary::safeStrlen($raw);
        if ($length < 1180) {
            throw new PaserkException("Secret key is too short: {$length}");
        }
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
        $this->throwIfInvalidProtocol($key->getProtocol());
        /// @SPEC DETAIL: Algorithm Lucidity

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
                $this->throwIfWrongKeyLength(
                    $key->getProtocol(),
                    Binary::safeStrlen($key->raw())
                );
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
     * @throws PaserkException
     */
    public function encodeV1(string $pk): string
    {
        $pem = preg_replace('#-{3,}(BEGIN|END) [^-]+-{3,}#', '', $pk);
        $decoded = Base64::decode(preg_replace('#[^A-Za-z0-9+/]#', '', $pem));
        $length = Binary::safeStrlen($decoded);
        if ($length < 1180) {
            throw new PaserkException("Secret key is too short: {$length}");
        }
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
        return Sid::encode(
            $key->getProtocol(),
            $this->encode($key)
        );
    }

    /**
     * @throws PaserkException
     */
    private function throwIfWrongKeyLength(ProtocolInterface $protocol, int $length): void
    {
        switch ($protocol::header()) {
            case 'v1':
                if ($length > 290) {
                    return;
                }
                break;
            case 'v2':
            case 'v4':
                if ($length === 64) {
                    return;
                }
                break;
            case 'v3':
                if ($length > 47) {
                    return;
                }
                break;
        }
        throw new PaserkException("Invalid secret key length: {$length}");
    }
}
