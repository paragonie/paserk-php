<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paserk\{
    IdCommonTrait,
    IdInterface,
    PaserkException
};
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
     *
     * @throws PaserkException
     * @throws SodiumException
     */
    public static function encodeLocal(SymmetricKey $key): string
    {
        if (Binary::safeStrlen($key->raw()) < 32) {
            throw new PaserkException("Key is too short");
        }
        $version = $key->getProtocol();
        return self::encode($version, (new Local($version))->encode($key));
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'lid';
    }
}
