<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PKE;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * @method ProtocolInterface getProtocol()
 */
trait PKETrait
{
    /**
     * @param KeyInterface $key
     * @throws PaserkException
     */
    protected function assertKeyVersion(KeyInterface $key): void
    {
        $protocol = static::getProtocol();
        if (!$key->getProtocol() instanceof $protocol) {
            throw new PaserkException("Invalid version for this secret key");
        }
    }
}
