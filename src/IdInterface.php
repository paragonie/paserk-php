<?php
declare(strict_types=1);
namespace ParagonIE\Paserk;

use ParagonIE\Paseto\ProtocolInterface;

/**
 * Interface IdInterface
 * @package ParagonIE\Paserk
 */
interface IdInterface
{
    /**
     * Get the PASERK type label for this ID
     *
     * @return string
     */
    public static function getTypeLabel(): string;

    /**
     * Calculate the Key-ID for a given PASERK.
     *
     * @param ProtocolInterface $version
     * @param string $paserk
     * @return string
     */
    public static function encode(ProtocolInterface $version, string $paserk): string;
}
