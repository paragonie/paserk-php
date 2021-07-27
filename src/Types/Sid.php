<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\IdCommonTrait;
use ParagonIE\Paserk\IdInterface;

/**
 * Class Sid
 * @package ParagonIE\Paserk\Types
 */
class Sid implements IdInterface
{
    use IdCommonTrait;

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'sid';
    }
}
