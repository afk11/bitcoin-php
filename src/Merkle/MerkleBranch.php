<?php

namespace BitWasp\Bitcoin\Merkle;


use BitWasp\Bitcoin\Crypto\Hash;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

class MerkleBranch
{
    /**
     * @param BufferInterface $leaf
     * @param BufferInterface[] $merkleBranch
     * @param int $index
     * @return BufferInterface
     */
    public function computeRootFromBranch(BufferInterface $leaf, array $merkleBranch, $index)
    {
        $hash = $leaf;

        foreach ($merkleBranch as $branch) {
            if ($index & 1) {
                $hash = Hash::sha256d(new Buffer($branch->getBinary() . $hash->getBinary()));
            } else {
                $hash = Hash::sha256d(new Buffer($hash->getBinary() . $branch->getBinary()));
            }
            $index = $index >> 1;
        }

        return $hash;
    }
}