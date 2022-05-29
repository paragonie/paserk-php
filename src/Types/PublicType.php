<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\ConstantTime\{
    Base64,
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paserk\{
    ConstraintTrait,
    PaserkException,
    PaserkTypeInterface,
    Util
};
use ParagonIE\Paseto\{
    Exception\InvalidVersionException,
    KeyInterface,
    Keys\AsymmetricPublicKey,
    Protocol\Version1,
    ProtocolCollection,
    ProtocolInterface
};
use function
    chunk_split,
    count,
    explode,
    hash_equals,
    implode,
    preg_replace;

/**
 * Class PublicType
 * @package ParagonIE\Paserk\Types
 */
class PublicType implements PaserkTypeInterface
{
    use ConstraintTrait;

    /**
     * @throws InvalidVersionException
     */
    public function __construct(ProtocolInterface ...$versions) {
        if (count($versions) > 0) {
            $this->collection = new ProtocolCollection(...$versions);
        } else {
            $this->collection = ProtocolCollection::v4();
        }
    }

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
        $version = Util::getPasetoVersion($pieces[0]);
        $this->throwIfInvalidProtocol($version);
        /// @SPEC DETAIL: Algorithm Lucidity

        if ($pieces[0] === 'k1') {
            return $this->decodeV1($pieces[2]);
        }
        return AsymmetricPublicKey::fromEncodedString(
            $pieces[2],
            $version
        );
    }

    /**
     * @param string $encoded
     * @return AsymmetricPublicKey
     * @throws \Exception
     */
    public function decodeV1(string $encoded): AsymmetricPublicKey
    {
        $raw = Base64UrlSafe::decode($encoded);
        if (Binary::safeStrlen($raw) < 200) {
            throw new PaserkException("Public key is too short");
        }
        $b64 = Base64::encode($raw);
        $pem = '-----BEGIN PUBLIC KEY-----' . "\n" .
            chunk_split($b64, 64, "\n") .
            '-----END PUBLIC KEY-----';
        return new AsymmetricPublicKey($pem, new Version1());
    }

    /**
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof AsymmetricPublicKey)) {
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
        $length = Binary::safeStrlen($decoded);
        if ($length < 292) {
            throw new PaserkException("Public key is too short: {$length}");
        }
        return Base64UrlSafe::encodeUnpadded($decoded);
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'public';
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
