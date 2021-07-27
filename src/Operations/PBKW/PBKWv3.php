<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PBKW;

use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Class PBKWv3
 * @package ParagonIE\Paserk\Operations\PBKW
 */
class PBKWv3 extends PBKWv1
{
    /**
     * @return string
     */
    public static function localHeader(): string
    {
        return 'k3.local-pw.';
    }

    /**
     * @return string
     */
    public static function secretHeader(): string
    {
        return 'k3.secret-pw.';
    }

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface
    {
        return new Version3();
    }
}
