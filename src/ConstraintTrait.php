<?php
declare(strict_types=1);
namespace ParagonIE\Paserk;

use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\ProtocolInterface;

trait ConstraintTrait
{
    /** @var ?ProtocolCollection $collection */
    protected $collection;

    /**
     * Specify the allowed protocols for this PASERK type.
     *
     * @param ProtocolCollection|null $collection
     * @return self
     */
    public function setProtocolsAllowed(?ProtocolCollection $collection = null): self
    {
        $this->collection = $collection;
        return $this;
    }

    /**
     * Throw a PASERK exception if the given PASETO version isn't permitted.
     *
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
