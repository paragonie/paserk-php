<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\IdCommonTrait;
use ParagonIE\Paserk\IdInterface;

/**
 * Class Pid
 * @package ParagonIE\Paserk\Types
 */
class Pid implements IdInterface
{
    use IdCommonTrait;

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'pid';
    }
}
