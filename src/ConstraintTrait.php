<?php
declare(strict_types=1);
namespace ParagonIE\Paserk;

use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\ProtocolInterface;

trait ConstraintTrait
{
    /** @var ?ProtocolCollection $collection */
    protected $collection;

    public function setProtocolsAllowed(?ProtocolCollection $collection = null): self
    {
        $this->collection = $collection;
        return $this;
    }

    /**
     * @param ProtocolInterface $given
     * @return void
     *
     * @throws PaserkException
     */
    public function throwIfInvalidProtocol(ProtocolInterface $given): void
    {
        if (is_null($this->collection)) {
            return;
        }
        if (!$this->collection->has($given)) {
            throw new PaserkException("Invalid protocol version");
        }
    }
}
