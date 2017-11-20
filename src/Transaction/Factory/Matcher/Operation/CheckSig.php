<?php

namespace BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation;

use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\PublicKey;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\Signature;

class CheckSig implements OperationInterface
{
    private $sig;
    private $pub;

    public function __construct()
    {
        $this->sig = new Signature();
        $this->pub = new PublicKey();
    }

    public function getInputTypes()
    {
        return [
            $this->sig,
            $this->pub,
        ];
    }

    public function getTemplates() {
        return [
            [$this->pub, Opcodes::OP_CHECKSIG],
            [$this->pub, Opcodes::OP_CHECKSIGVERIFY],
        ];
    }
}
