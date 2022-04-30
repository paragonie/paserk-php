<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\Key;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Protocol\Version1;

/**
 * Class SealingPublicKey
 * @package ParagonIE\Paserk\Operations\Key
 */
class SealingPublicKey extends AsymmetricPublicKey
{
    /**
     * @return AsymmetricPublicKey
     * @throws PaserkException
     */
    public function toPasetoKey(): AsymmetricPublicKey
    {
        if ($this->protocol instanceof Version1) {
            throw new PaserkException("Version 1 keys cannot be converted!");
        }

        return new AsymmetricPublicKey(
            $this->key,
            $this->protocol
        );
    }
}
