<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\{
    ConstraintTrait,
    PaserkException,
    PaserkTypeInterface,
    Util
};
use ParagonIE\Paseto\{Exception\InvalidVersionException,
    Exception\PasetoException,
    KeyInterface,
    Keys\AsymmetricPublicKey,
    ProtocolCollection,
    ProtocolInterface};
use Exception;
use SodiumException;
use function
    count,
    explode,
    hash_equals,
    implode;

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
     * @throws Exception
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

        return AsymmetricPublicKey::fromEncodedString(
            $pieces[2],
            $version
        );
    }

    /**
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
     * @throws PasetoException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof AsymmetricPublicKey)) {
            throw new PaserkException('Only symmetric keys can be serialized as kx.local.');
        }
        $this->throwIfInvalidProtocol($key->getProtocol());
        /// @SPEC DETAIL: Algorithm Lucidity

        $version = Util::getPaserkHeader($key->getProtocol());
        return match ($version) {
            'k3', 'k4' => implode('.', [
                $version,
                self::getTypeLabel(),
                $key->encode()
            ]),
            default => throw new PaserkException('Unknown version'),
        };
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
     *
     * @throws PaserkException
     * @throws SodiumException
     */
    public function id(KeyInterface $key): string
    {
        return Pid::encode(
            $key->getProtocol(),
            $this->encode($key)
        );
    }
}
