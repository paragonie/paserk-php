<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use TypeError;

/**
 * Class Wrap
 * @package ParagonIE\Paserk\Operations
 */
class Wrap
{
    /** @var WrapInterface $wrapper */
    protected $wrapper;

    /**
     * Wrap constructor.
     * @param WrapInterface $wrapper
     */
    public function __construct(WrapInterface $wrapper)
    {
        $this->wrapper = $wrapper;
    }

    /**
     * @param SymmetricKey $key
     * @return string
     * @throws PaserkException
     */
    public function localWrap(SymmetricKey $key): string
    {
        $version = Util::getPaserkHeader($key->getProtocol());
        $header = $version . '.local-wrap.' . $this->wrapper::customId() . '.';
        $wrapped = $this->wrapper->wrapKey($header, $key);
        return $header . $wrapped;
    }

    /**
     * @param string $key
     * @return SymmetricKey
     */
    public function localUnwrap(string $key): SymmetricKey
    {
        $unwrapped = $this->wrapper->unwrapKey($key);
        if (!($unwrapped instanceof SymmetricKey)) {
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
