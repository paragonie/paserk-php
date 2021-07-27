<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Interface PBKWInterface
 * @package ParagonIE\Paserk\Operations
 */
interface PBKWInterface
{
    /**
     * @return string
     */
    public static function localHeader(): string;

    /**
     * @return string
     */
    public static function secretHeader(): string;

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface;

    /**
     * @param KeyInterface $key
     * @param HiddenString $password
     * @param array $options
     * @return string
     */
    public function wrapWithPassword(
        KeyInterface $key,
        HiddenString $password,
        array $options = []
    ): string;

    /**
     * @param string $header
     * @param string $wrapped
     * @param HiddenString $password
     * @return KeyInterface
     */
    public function unwrapWithPassword(
        string $header,
        string $wrapped,
        HiddenString $password
    ): KeyInterface;
}
