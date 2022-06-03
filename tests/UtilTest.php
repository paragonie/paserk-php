<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests;

use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;

/**
 * Class UtilTest
 * @package ParagonIE\Paserk\Tests
 *
 * @covers Util
 */
class UtilTest extends TestCase
{
    public function testGetPaserkHeader()
    {
        $this->assertSame('k3', Util::getPaserkHeader(new Version3()));
        $this->assertSame('k4', Util::getPaserkHeader(new Version4()));
    }
}
