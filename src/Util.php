<?php
declare(strict_types=1);
namespace ParagonIE\Paserk;

use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use SodiumException;

/**
 * Class Util
 * @package ParagonIE\Paserk
 */
class Util
{
    /**
     * Given a PASERK version identifier string ("kX"), return the PASETO protocol
     * that corresponds to this version.
     *
     * @param string $version
     *
     * @return ProtocolInterface
     * @throws PaserkException
     */
    public static function getPasetoVersion(string $version): ProtocolInterface
    {
        return match ($version) {
            'k3' => new Version3(),
            'k4' => new Version4(),
            default => throw new PaserkException('Invalid version provided'),
        };
    }

    /**
     * Given a PASETO protocol version, return the PASERK version identifier string ("kX").
     *
     * @param ProtocolInterface $pasetoVersion
     * @return string
     * @throws PaserkException
     */
    public static function getPaserkHeader(ProtocolInterface $pasetoVersion): string
    {
        if ($pasetoVersion instanceof Version3) {
            return 'k3';
        }
        if ($pasetoVersion instanceof Version4) {
            return 'k4';
        }
        throw new PaserkException('Invalid version provided');
    }

    /**
     * Attempt to wipe memory.
     *
     * If you have ext/sodium installed, sodium_memzero() will do the trick.
     *
     * If you don't, we'll do a best-effort with a self-XOR to zero. This
     * isn't guaranteed to work. If you care about security, use ext/sodium.
     *
     * @param string $byref
     * @psalm-param-out ?string $byref
     */
    public static function wipe(string &$byref): void
    {
        try {
            sodium_memzero($byref);
        } catch (SodiumException $ex) {
            $byref ^= $byref;
            unset($byref);
            unset($ex); // We know what this is
        }
    }
}
