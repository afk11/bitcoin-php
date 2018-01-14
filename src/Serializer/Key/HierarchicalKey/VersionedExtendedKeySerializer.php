<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Serializer\Key\HierarchicalKey;

use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKey;
use BitWasp\Bitcoin\Serializer\Types;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Exceptions\ParserOutOfRange;
use BitWasp\Buffertools\Parser;

class VersionedExtendedKeySerializer
{
    /**
     * @var \BitWasp\Buffertools\Types\ByteString
     */
    private $bytestring4;

    /**
     * @var \BitWasp\Buffertools\Types\Uint8
     */
    private $uint8;

    /**
     * @var \BitWasp\Buffertools\Types\Uint32
     */
    private $uint32;

    /**
     * @var \BitWasp\Buffertools\Types\ByteString
     */
    private $bytestring32;

    /**
     * @var \BitWasp\Buffertools\Types\ByteString
     */
    private $bytestring33;

    /**
     * @throws \Exception
     */
    public function __construct()
    {
        $this->bytestring4 = Types::bytestring(4);
        $this->uint8 = Types::uint8();
        $this->uint32 = Types::uint32();
        $this->bytestring32 = Types::bytestring(32);
        $this->bytestring33 = Types::bytestring(33);
    }

    /**
     * @param string $hexPrefix
     * @param HierarchicalKey $key
     * @return BufferInterface
     * @throws \Exception
     */
    public function serialize(string $hexPrefix, HierarchicalKey $key): BufferInterface
    {
        if ($key->isPrivate()) {
            $data = new Buffer("\x00". $key->getPrivateKey()->getBinary(), 33);
        } else {
            $data = $key->getPublicKey()->getBuffer();
        }

        return new Buffer(
            $this->bytestring4->write(Buffer::hex($hexPrefix, 4)) .
            $this->uint8->write($key->getDepth()) .
            $this->uint32->write($key->getFingerprint()) .
            $this->uint32->write($key->getSequence()) .
            $this->bytestring32->write($key->getChainCode()) .
            $this->bytestring33->write($data)
        );
    }

    /**
     * @param Parser $parser
     * @return array
     * @throws ParserOutOfRange
     */
    public function fromParser(Parser $parser): array
    {
        try {
            list ($bytes, $depth, $parentFingerprint, $sequence, $chainCode, $keyData) = [
                $this->bytestring4->read($parser),
                (int) $this->uint8->read($parser),
                (int) $this->uint32->read($parser),
                (int) $this->uint32->read($parser),
                $this->bytestring32->read($parser),
                $this->bytestring33->read($parser),
            ];

            $bytes = $bytes->getHex();
        } catch (ParserOutOfRange $e) {
            throw new ParserOutOfRange('Failed to extract HierarchicalKey from parser');
        }

        return [$bytes, $depth, $parentFingerprint, $sequence, $chainCode, $keyData];
    }

    /**
     * @param BufferInterface $buffer
     * @return array
     * @throws ParserOutOfRange
     */
    public function parse(BufferInterface $buffer): array
    {
        return $this->fromParser(new Parser($buffer));
    }
}
