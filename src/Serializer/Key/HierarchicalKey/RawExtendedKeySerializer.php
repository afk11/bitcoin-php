<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Serializer\Key\HierarchicalKey;

use BitWasp\Bitcoin\Crypto\EcAdapter\Adapter\EcAdapterInterface;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Exceptions\ParserOutOfRange;
use BitWasp\Buffertools\Parser;

class RawExtendedKeySerializer
{
    /**
     * @var EcAdapterInterface
     */
    private $ecAdapter;

    /**
     * RawExtendedKeySerializer constructor.
     * @param EcAdapterInterface $ecAdapter
     */
    public function __construct(EcAdapterInterface $ecAdapter)
    {
        $this->ecAdapter = $ecAdapter;
    }

    /**
     * @param RawKeyParams $keyParams
     * @return BufferInterface
     * @throws \Exception
     */
    public function serialize(RawKeyParams $keyParams): BufferInterface
    {
        return new Buffer(
            pack(
                "H*CNN",
                $keyParams->getPrefix(), $keyParams->getDepth(), $keyParams->getParentFingerprint(), $keyParams->getSequence()
            ) .
            $keyParams->getChainCode()->getBinary() .
            $keyParams->getKeyData()->getBinary()
        );
    }

    /**
     * @param Parser $parser
     * @return RawKeyParams
     * @throws ParserOutOfRange
     */
    public function fromParser(Parser $parser): RawKeyParams
    {
        try {
            $prefix = $parser->readBytes(4)->getHex();
            $p = unpack("C1depth/NparFpr/Nsequence", $parser->readBytes(1+4+4)->getBinary());
            return new RawKeyParams(
                $prefix,
                $p['depth'],
                $p['parFpr'],
                $p['sequence'],
                $parser->readBytes(32),
                $parser->readBytes(33)
            );
        } catch (ParserOutOfRange $e) {
            throw new ParserOutOfRange('Failed to extract HierarchicalKey from parser');
        }
    }
}
