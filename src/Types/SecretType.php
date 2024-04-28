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
    Keys\AsymmetricSecretKey,
    ProtocolCollection,
    ProtocolInterface
};
use Exception;
use SodiumException;
use function
    count,
    explode,
    hash_equals,
    implode;

/**
 * Class SecretType
 * @package ParagonIE\Paserk\Types
 */
class SecretType implements PaserkTypeInterface
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
     * Decode a PASERK string into a PASETO secret key
     *
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

        $rawKey = Base64UrlSafe::decode($pieces[2]);
        $this->throwIfWrongKeyLength($version, Binary::safeStrlen($rawKey));
        return new AsymmetricSecretKey($rawKey, $version);
    }

    /**
     * Encode a PASETO secret key into a PASERK string
     *
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
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'secret';
    }

    /**
     * Get the lid PASERK for the PASERK representation of this secret key.
     *
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
     * @throws SodiumException
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
            case 'v3':
                if ($length >= 47) {
                    return;
                }
                break;
            case 'v4':
                if ($length === 64) {
                    return;
                }
                break;
        }
        throw new PaserkException("Invalid secret key length: $length");
    }
}
