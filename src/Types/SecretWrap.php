<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\Operations\Wrap\Pie;
use ParagonIE\Paserk\Operations\Wrap;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\PaserkTypeInterface;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;

/**
 * Class SecretWrap
 * @package ParagonIE\Paserk\Types
 */
class SecretWrap implements PaserkTypeInterface
{
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
     */
    public static function initWithKey(SymmetricKey $key): self
    {
        return new self(new Wrap(new Pie($key)));
    }

    public function decode(string $paserk): KeyInterface
    {
        return $this->wrap->secretUnwrap($paserk);
    }

    /**
     * @param KeyInterface $key
     * @return string
     * @throws PaserkException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof AsymmetricSecretKey)) {
            throw new PaserkException('Only asymmetric secret keys are allowed here');
        }
        $localId = (new SecretType())->encode($key);
        if (!array_key_exists($localId, $this->localCache)) {
            $this->localCache[$localId] = $this->wrap->secretWrap($key);
        }
        return $this->localCache[$localId];
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
