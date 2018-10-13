<?php

namespace BitWasp\Bitcoin\Crypto\EcAdapter\Signature;

use BitWasp\Bitcoin\Crypto\EcAdapter\Key\PublicKeyInterface;
use BitWasp\Buffertools\BufferInterface;

interface SignerInterface
{
    /**
     * @return PublicKeyInterface
     */
    public function getPublicKey();

    /**
     * @param BufferInterface $msg32
     * @return SignatureInterface
     */
    public function sign(BufferInterface $msg32);
}
