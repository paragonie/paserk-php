<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paserk\ConstraintTrait;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\PaserkTypeInterface;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\ProtocolInterface;
use function
    count,
    explode,
    implode;

/**
 * Class Local
 * @package ParagonIE\Paserk\Types
 */
class Local implements PaserkTypeInterface
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
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof SymmetricKey)) {
            throw new PaserkException('Only symmetric keys can be serialized as kx.local.');
        }
        $this->throwIfInvalidProtocol($key->getProtocol());
        /// @SPEC DETAIL: Algorithm Lucidity

        if (Binary::safeStrlen($key->raw()) < 32) {
            throw new PaserkException("Symmetric keys must be 256-bit");
        }

        $version = Util::getPaserkHeader($key->getProtocol());
        return implode('.', [$version, self::getTypeLabel(), $key->encode()]);
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
        $decoded = Base64UrlSafe::decode($pieces[2]);
        if (Binary::safeStrlen($decoded) < 32) {
            throw new PaserkException("Symmetric keys must be 256-bit");
        }

        return new SymmetricKey(
            $decoded,
            $version
        );
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'local';
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
        return Lid::encode(
            $key->getProtocol(),
            $this->encode($key)
        );
    }
}
