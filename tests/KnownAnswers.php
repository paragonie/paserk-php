<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests;

use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};

abstract class KnownAnswers extends TestCase
{
    /** @var string $dir */
    protected $dir;

    /** @var ProtocolInterface[] $versions */
    protected $versions;

    public function setUp(): void
    {
        $this->dir = __DIR__ . '/test-vectors';
        $this->versions = [new Version1, new Version2, new Version3, new Version4];
    }

    /**
     * @param ProtocolInterface $version
     * @param string $name
     * @param array $tests
     */
    abstract protected function genericTest(ProtocolInterface $version, string $name, array $tests): void;

    /**
     * @param ProtocolInterface $v
     * @param string $filename
     */
    protected function doJsonTest(ProtocolInterface $v, string $filename): void
    {
        $json = $this->loadTestFile($filename);
        $this->genericTest($v, $json['name'], $json['tests']);
    }

    /**
     * @param string $filename
     * @return array
     */
    protected function loadTestFile(string $filename): array
    {

        if (!is_readable($this->dir . '/' . $filename)) {
            $this->markTestSkipped('File not found: ' . $filename);
        }
        $decodedFile = json_decode(
            file_get_contents($this->dir . '/' . $filename),
            true
        );
        if (!is_array($decodedFile)) {
            $this->fail('Decoded JSON file is not an array: ' . $filename);
        }
        return $decodedFile;
    }

}
