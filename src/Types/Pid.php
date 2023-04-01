<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use FG\ASN1\Exception\ParserException;
use ParagonIE\Paserk\{
    IdCommonTrait,
    IdInterface,
    PaserkException
};
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey;
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
     *
     * @throws PaserkException
     * @throws SodiumException
     */
    public static function encodePublic(AsymmetricPublicKey $pk): string
    {
        try {
            $version = $pk->getProtocol();
            return self::encode($version, (new PublicType($version))->encode($pk));
        } catch (InvalidVersionException|ParserException|PasetoException|PaserkException $ex) {
            throw new PaserkException("Invalid public key", 0, $ex);
        }
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'pid';
    }
}
