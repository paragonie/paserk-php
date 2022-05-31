<?php
declare(strict_types=1);
namespace ParagonIE\Paserk;

use ParagonIE\Paseto\KeyInterface;

/**
 * Interface PaserkTypeInterface
 * @package ParagonIE\Paserk
 */
interface PaserkTypeInterface
{
    /**
     * Decode a PASERK string into a PASETO key.
     *
     * @param string $paserk
     * @return KeyInterface
     */
    public function decode(string $paserk): KeyInterface;

    /**
     * Encode a PASETO key into a PASERK string.
     *
     * @param KeyInterface $key
     * @return string
     */
    public function encode(KeyInterface $key): string;

    /**
     * Get the label for this PASERK Type.
     *
     * @return string
     */
    public static function getTypeLabel(): string;

    /**
     * Get the appropriate ID string.
     *
     * @see Lid, Pid, Sid
     *
     * @param KeyInterface $key
     * @return string
     */
    public function id(KeyInterface $key): string;
}
