<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\Key;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use Exception;

/**
 * Class SealingPublicKey
 * @package ParagonIE\Paserk\Operations\Key
 */
class SealingPublicKey extends AsymmetricPublicKey
{
    /**
     * @return AsymmetricPublicKey
     *
     * @throws PaserkException
     * @throws Exception
     */
    public function toPasetoKey(): AsymmetricPublicKey
    {
        return new AsymmetricPublicKey(
            $this->key,
            $this->protocol
        );
    }
}
