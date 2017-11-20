<?php

namespace BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation;

use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\DataBlob;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\FixedLengthBlob;

class Hashlock implements OperationInterface
{
    private static $hashSize = [
        Opcodes::OP_HASH160 => 20,
    ];

    /**
     * @var DataBlob
     */
    private $inputData;

    /**
     * @var FixedLengthBlob
     */
    private $hashBlob;

    /**
     * @var int
     */
    private $hashOp;

    /**
     * Hashlock constructor.
     * @param int $opcode
     */
    public function __construct($opcode)
    {
        if (!array_key_exists($opcode, self::$hashSize)) {
            throw new \RuntimeException("Not a hashing op");
        }

        $this->inputData = new DataBlob();
        $this->hashBlob = new FixedLengthBlob(self::$hashSize[$opcode]);
        $this->hashOp = $opcode;
    }

    /**
     * @return int
     */
    public function getHashSize()
    {
        return $this->hashBlob->getLength();
    }

    public function getInputTypes()
    {
        return [
            $this->inputData,
        ];
    }

    public function getTemplates() {
        return [
            [$this->hashOp, $this->hashBlob, Opcodes::OP_EQUAL],
            [$this->hashOp, $this->hashBlob, Opcodes::OP_EQUALVERIFY],
        ];
    }
}
