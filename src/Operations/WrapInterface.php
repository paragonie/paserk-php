<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\Paseto\KeyInterface;

/**
 * Interface WrapInterface
 * @package ParagonIE\Paserk\Operations
 */
interface WrapInterface
{
    /**
     * Returns a custom ID ([A-Za-z0-9\-]+) for the encryption format.
     *
     * @return string
     */
    public static function customId(): string;

    /**
     * @param string $header
     * @param KeyInterface $key
     * @return string
     */
    public function wrapKey(string $header, KeyInterface $key): string;

    /**
     * @param string $wrapped
     * @return KeyInterface
     */
    public function unwrapKey(string $wrapped): KeyInterface;
}
