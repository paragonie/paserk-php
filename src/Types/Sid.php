<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\{
    IdCommonTrait,
    IdInterface,
    PaserkException
};
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Keys\Base\AsymmetricSecretKey;
use SodiumException;

/**
 * Class Sid
 * @package ParagonIE\Paserk\Types
 */
class Sid implements IdInterface
{
    use IdCommonTrait;

    /**
     * Calculate the PASERK secret key ID for a given AsymmetricSecretKey.
     *
     * @param AsymmetricSecretKey $sk
     * @return string
     *
     * @throws InvalidVersionException
     * @throws PaserkException
     * @throws SodiumException
     */
    public static function encodeSecret(AsymmetricSecretKey $sk): string
    {
        $version = $sk->getProtocol();
        return self::encode($version, (new SecretType($version))->encode($sk));
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'sid';
    }
}
