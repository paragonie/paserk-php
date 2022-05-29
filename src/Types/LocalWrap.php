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
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\ProtocolCollection;
use function array_key_exists;

/**
 * Class LocalWrap
 * @package ParagonIE\Paserk\Types
 */
class LocalWrap implements PaserkTypeInterface
{
    use ConstraintTrait;

    /** @var array<string, string> */
    protected $localCache = [];

    /** @var Wrap $wrap */
    protected $wrap;

    /**
     * LocalWrap constructor.
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
     * @throws PaserkException
     */
    public function decode(string $paserk): KeyInterface
    {
        $out = $this->wrap->localUnwrap($paserk);
        $this->throwIfInvalidProtocol($out->getProtocol());
        /// @SPEC DETAIL: Algorithm Lucidity

        return $out;
    }

    /**
     * @param KeyInterface $key
     * @return string
     *
     * @throws InvalidVersionException
     * @throws PaserkException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof SymmetricKey)) {
            throw new PaserkException('Only symmetric keys are allowed here');
        }
        $this->throwIfInvalidProtocol($key->getProtocol());
        /// @SPEC DETAIL: Algorithm Lucidity

        $localId = (new Local($this->wrap->getProtocol()))->encode($key);
        if (!array_key_exists($localId, $this->localCache)) {
            $this->localCache[$localId] = $this->wrap->localWrap($key);
        }
        return $this->localCache[$localId];
    }

    public static function getTypeLabel(): string
    {
        return 'local-wrap';
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
        return Lid::encode(
            $key->getProtocol(),
            $this->encode($key)
        );
    }
}
