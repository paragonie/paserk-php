<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PBKW;

use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Class PBKWv4
 * @package ParagonIE\Paserk\Operations\PBKW
 */
class PBKWv4 extends PBKWv2
{
    /**
     * @return string
     */
    public static function localHeader(): string
    {
        return 'k4.local-pw.';
    }

    /**
     * @return string
     */
    public static function secretHeader(): string
    {
        return 'k4.secret-pw.';
    }


    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface
    {
        return new Version4();
    }
}
