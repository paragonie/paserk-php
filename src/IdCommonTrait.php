<?php
declare(strict_types=1);
namespace ParagonIE\Paserk;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paserk\Types\{
    Lid,
    Pid,
    Sid
};
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use SodiumException;
use function
    hash,
    sodium_crypto_generichash;

/**
 * Trait IdCommonTrait
 * @package ParagonIE\Paserk
 *
 * @method static string getTypeLabel()
 * @see Lid, Pid, Sid
 */
trait IdCommonTrait
{
    /**
     * @param array $args
     * @throws PaserkException
     */
    final public static function decode(...$args): void
    {
        throw new PaserkException(
            "PASERK IDs are a one-way transformation. There is no 'decode' option."
        );
    }

    /**
     * Calculate the Key-ID for a given PASERK.
     *
     * @param ProtocolInterface $version
     * @param string $paserk
     * @return string
     *
     * @throws PaserkException
     * @throws SodiumException
     */
    public static function encode(ProtocolInterface $version, string $paserk): string
    {
        $header = Util::getPaserkHeader($version) . '.' . self::getTypeLabel() . '.';
        if ($version instanceof Version1 || $version instanceof Version3) {
            $hash = Binary::safeSubstr(
                hash('sha384', $header . $paserk, true),
                0,
                33
            );
        } elseif ($version instanceof Version2 || $version instanceof Version4) {
            $hash = sodium_crypto_generichash(
                $header . $paserk,
                '',
                33
            );
        } else {
            throw new PaserkException('Invalid protocol version');
        }
        return $header . Base64UrlSafe::encode($hash);
    }
}
