<?php

namespace BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation;


interface OperationInterface
{
    public function getInputTypes();

    /**
     * @return array[]
     */
    public function getTemplates();
}
