<?php

namespace BitWasp\Bitcoin\Transaction\Factory;

use BitWasp\Bitcoin\Transaction\Factory\Matcher\MatcherState;

class Template
{
    private $operations = [];

    public function __construct(
        array $operations
    )
    {
        $this->operations = $operations;
    }

    public function matches(MatcherState $state) {
        echo "\nBegin template matching\n";
        foreach ($this->operations as $op) {
            echo "Checking operation \n";
            var_dump($op);
            if (!$state->checkTemplate($op)) {
                return false;
            }
        }

        return true;
    }
}
