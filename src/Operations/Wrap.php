<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    Base\SymmetricKey as BaseSymmetricKey,
    SymmetricKey
};
use ParagonIE\Paseto\ProtocolInterface;
use TypeError;

/**
 * Class Wrap
 * @package ParagonIE\Paserk\Operations
 */
class Wrap
{
    /** @var WrapInterface $wrapper */
    protected WrapInterface $wrapper;

    /**
     * Wrap constructor.
     * @param WrapInterface $wrapper
     */
    public function __construct(WrapInterface $wrapper)
    {
        $this->wrapper = $wrapper;
    }

    /**
     * @return ProtocolInterface
     */
    public function getProtocol(): ProtocolInterface
    {
        return $this->wrapper->getProtocol();
    }

    /**
     * @param BaseSymmetricKey $key
     * @return string
     * @throws PaserkException
     */
    public function localWrap(BaseSymmetricKey $key): string
    {
        $version = Util::getPaserkHeader($key->getProtocol());
        $header = $version . '.local-wrap.' . $this->wrapper::customId() . '.';
        $wrapped = $this->wrapper->wrapKey($header, $key);
        return $header . $wrapped;
    }

    /**
     * @param string $key
     * @return BaseSymmetricKey
     */
    public function localUnwrap(string $key): BaseSymmetricKey
    {
        $unwrapped = $this->wrapper->unwrapKey($key);
        if (!($unwrapped instanceof BaseSymmetricKey)) {
            throw new TypeError('Invalid type returned from unwrapKey()');
        }
        return $unwrapped;
    }

    /**
     * @param AsymmetricSecretKey $key
     * @return string
     * @throws PaserkException
     */
    public function secretWrap(AsymmetricSecretKey $key): string
    {
        $version = Util::getPaserkHeader($key->getProtocol());
        $header = $version . '.secret-wrap.' . $this->wrapper::customId() . '.';
        $wrapped = $this->wrapper->wrapKey($header, $key);
        return $header . $wrapped;
    }

    /**
     * @param string $key
     * @return AsymmetricSecretKey
     */
    public function secretUnwrap(string $key): AsymmetricSecretKey
    {
        $unwrapped = $this->wrapper->unwrapKey($key);
        if (!($unwrapped instanceof AsymmetricSecretKey)) {
            throw new TypeError('Invalid type returned from unwrapKey()');
        }
        return $unwrapped;
    }
}
