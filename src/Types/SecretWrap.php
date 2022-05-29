<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\ConstraintTrait;
use ParagonIE\Paserk\Operations\Wrap\Pie;
use ParagonIE\Paserk\Operations\Wrap;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\PaserkTypeInterface;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\ProtocolCollection;
use function array_key_exists;

/**
 * Class SecretWrap
 * @package ParagonIE\Paserk\Types
 */
class SecretWrap implements PaserkTypeInterface
{
    use ConstraintTrait;

    /** @var array<string, string> */
    protected $localCache = [];

    /** @var Wrap $wrap */
    protected $wrap;

    /**
     * SecretWrap constructor.
     * @param Wrap $wrap
     */
    public function __construct(Wrap $wrap)
    {
        $this->wrap = $wrap;
        $this->localCache = [];
    }

    /**
     * @param SymmetricKey $key
     * @return static
     *
     * @throws InvalidVersionException
     */
    public static function initWithKey(SymmetricKey $key): self
    {
        $init = new self(new Wrap(new Pie($key)));
        $init->setProtocolsAllowed(new ProtocolCollection($key->getProtocol()));
        return $init;
    }

    /**
     * @param string $paserk
     * @return KeyInterface
     * @throws PaserkException
     */
    public function decode(string $paserk): KeyInterface
    {
        $unwrapped = $this->wrap->secretUnwrap($paserk);
        $this->throwIfInvalidProtocol($unwrapped->getProtocol());
        /// @SPEC DETAIL: Algorithm Lucidity
        return $unwrapped;
    }

    /**
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
     * @throws InvalidVersionException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof AsymmetricSecretKey)) {
            throw new PaserkException('Only asymmetric secret keys are allowed here');
        }
        $this->throwIfInvalidProtocol($key->getProtocol());
        /// @SPEC DETAIL: Algorithm Lucidity
        $secretId = (new SecretType($this->wrap->getProtocol()))->encode($key);
        if (!array_key_exists($secretId, $this->localCache)) {
            $this->localCache[$secretId] = $this->wrap->secretWrap($key);
        }
        return $this->localCache[$secretId];
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'secret-wrap';
    }

    /**
     * @param KeyInterface $key
     * @return string
     *
     * @throws InvalidVersionException
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
}
