<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\IdCommonTrait;
use ParagonIE\Paserk\IdInterface;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use SodiumException;

/**
 * Class Pid
 * @package ParagonIE\Paserk\Types
 */
class Pid implements IdInterface
{
    use IdCommonTrait;

    /**
     * @param AsymmetricPublicKey $pk
     * @return string
     * @throws PaserkException
     * @throws SodiumException
     */
    public static function encodePublic(AsymmetricPublicKey $pk): string
    {
        return self::encode($pk->getProtocol(), (new PublicType())->encode($key));
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'pid';
    }
}
