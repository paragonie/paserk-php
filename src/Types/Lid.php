<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\IdCommonTrait;
use ParagonIE\Paserk\IdInterface;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use SodiumException;

/**
 * Class Lid
 * @package ParagonIE\Paserk\Types
 */
class Lid implements IdInterface
{
    use IdCommonTrait;

    /**
     * @param SymmetricKey $key
     * @return string
     * @throws PaserkException
     * @throws SodiumException
     */
    public static function encodeLocal(SymmetricKey $key): string
    {
        return self::encode($key->getProtocol(), (new Local())->encode($key));
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'lid';
    }
}
