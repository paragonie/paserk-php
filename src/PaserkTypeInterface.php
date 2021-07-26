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
     * @param string $paserk
     * @return KeyInterface
     */
    public function decode(string $paserk): KeyInterface;

    /**
     * @param KeyInterface $key
     * @return string
     */
    public function encode(KeyInterface $key): string;

    /**
     * @return string
     */
    public static function getTypeLabel(): string;

    /**
     * @param KeyInterface $key
     * @return string
     */
    public function id(KeyInterface $key): string;
}
