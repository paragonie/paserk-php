<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\IdCommonTrait;
use ParagonIE\Paserk\IdInterface;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use SodiumException;

/**
 * Class Sid
 * @package ParagonIE\Paserk\Types
 */
class Sid implements IdInterface
{
    use IdCommonTrait;

    /**
     * @param AsymmetricSecretKey $sk
     * @return string
     * @throws PaserkException
     * @throws SodiumException
     */
    public static function encodeSecret(AsymmetricSecretKey $sk): string
    {
        return self::encode($sk->getProtocol(), (new SecretType())->encode($sk));
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'sid';
    }
}
