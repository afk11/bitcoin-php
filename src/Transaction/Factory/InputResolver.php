<?php

namespace BitWasp\Bitcoin\Transaction\Factory;


use BitWasp\Bitcoin\Script\Interpreter\Checker;
use BitWasp\Bitcoin\Script\Interpreter\Interpreter;
use BitWasp\Bitcoin\Script\Interpreter\Stack;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Parser\Operation;
use BitWasp\Bitcoin\Script\ScriptInterface;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\MatcherState;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation\OperationInterface;
use BitWasp\Bitcoin\Transaction\TransactionInterface;

class InputResolver
{
    /**
     * @var TransactionInterface
     */
    private $transaction;

    /**
     * @var Interpreter
     */
    private $interpreter;

    /**
     * @var array|OperationInterface[]
     */
    private $operations;

    /**
     * @var bool[]
     */
    private $logicalPath;

    /**
     * @var int
     */
    private $nInput;

    /**
     * @var Checker
     */
    private $checker;

    /**
     * InputResolver constructor.
     * @param TransactionInterface $transaction
     * @param int $nIn
     * @param bool[] $logicalPath
     * @param Checker $checker
     * @param OperationInterface[] $operations
     */
    public function __construct(
        TransactionInterface $transaction,
        $nIn,
        $logicalPath,
        Checker $checker,
        array $operations
    ) {
        $this->interpreter = new Interpreter();
        $this->transaction = $transaction;
        $this->logicalPath = $logicalPath;
        $this->operations = $operations;
        $this->checker = $checker;
        $this->nInput = $nIn;
    }

    /**
     * @param Operation $operation
     * @param Stack $mainStack
     * @param bool[] $pathData
     * @return Conditional
     */
    public function extractConditionalOp(Operation $operation, Stack $mainStack, array &$pathData)
    {
        $opValue = null;

        if (!$mainStack->isEmpty()) {
            if (count($pathData) === 0) {
                throw new \RuntimeException("Extracted conditional op (including mainstack) without corresponding element in path data");
            }

            $opValue = $this->interpreter->castToBool($mainStack->pop());
            $dataValue = array_shift($pathData);
            if ($opValue !== $dataValue) {
                throw new \RuntimeException("Current stack doesn't follow branch path");
            }
        } else {
            if (count($pathData) === 0) {
                throw new \RuntimeException("Extracted conditional op without corresponding element in path data");
            }

            $opValue = array_shift($pathData);
        }

        $conditional = new Conditional($operation->getOp());

        if ($opValue !== null) {
            if (!is_bool($opValue)) {
                throw new \RuntimeException("Sanity check, path value (likely from pathData) was not a bool");
            }

            $conditional->setValue($opValue);
        }

        return $conditional;
    }

    private function decodePushOnly(ScriptInterface $script) {
        $inputStack = $script->getScriptParser()->decode();
        $data = [];
        foreach ($inputStack as $value) {
            if (!$value->isPush()) {
                throw new \RuntimeException("Not a pushonly script");
            } else {
                $data[] = $value;
            }
        }
        return $data;
    }

    public function match(ScriptInterface $script)
    {

        $inputSig = $this->transaction->getInput($this->nInput)->getScript();
        $inputStack = $this->decodePushOnly($inputSig);

        $state = new ResolverState($this->logicalPath, $inputStack);
        $parser = $script->getScriptParser();

        $steps = [];
        foreach ($parser->decode() as  $ii => $op) {
            echo " --------- ".$ii." --------- ".PHP_EOL;
            if ($op->isPush()) {
                echo "  [".$op->getData()->getHex()."]\n";
            } else {
                echo "  [".$script->getOpcodes()->getOp($op->getOp())."]\n";
            }
            echo " -------------------- ".PHP_EOL;

            $fExec = !$this->interpreter->checkExec($state->vfStack(), false);

            if ($op->isLogical()) {
                switch ($op->getOp()) {
                    case Opcodes::OP_IF:
                    case Opcodes::OP_NOTIF:
                        $value = false;
                        if ($fExec) {
                            // Pop from mainStack if $fExec
                            $step = $this->extractConditionalOp($op, $state->stack(), $pathCopy);

                            // the Conditional has a value in this case:
                            $value = $step->getValue();

                            // Connect the last operation (if there is one)
                            // with the last step with isRequired==$value
                            // todo: check this part out..
                            for ($j = count($steps) - 1; $j >= 0; $j--) {
                                if ($steps[$j] instanceof Checksig && $value === $steps[$j]->isRequired()) {
                                    $step->providedBy($steps[$j]);
                                    break;
                                }
                            }
                        } else {
                            $step = new Conditional($op->getOp());
                        }

                        $steps[] = $step;

                        if ($op->getOp() === Opcodes::OP_NOTIF) {
                            $value = !$value;
                        }

                        $state->vfStack()->push($value);
                        return $step;

                    case Opcodes::OP_ENDIF:
                        $state->vfStack()->pop();
                        break;
                    case Opcodes::OP_ELSE:
                        $state->vfStack()->push(!$state->vfStack()->pop());
                        break;
                }

                return null;
            }

            if ($fExec) {
                $state->withOperation($op);

                foreach ($this->operations as $operation) {
                    if ($state->checkTemplate($operation)) {

                        echo "CLEANUP!\n";
                        $state->removeTemplateOps($operation);
                        echo "We matched an operation - better cleanup!\n";
                        break;
                    }
                }

                if ($op->isPush()) {
                    $state->stack()->push($op->getData());
                } else {
                    switch ($op->getOp()) {
                        case Opcodes::OP_DUP:

                            break;
                    }
                }
                //echo "chk template: " . ($template === null ?'null': "have template: " . $template[0]) . PHP_EOL;
            }
        }

        //print_R($state);
    }

    private function matchOperation(ResolverState $state, OperationInterface $operation) {
        foreach ($operation->getTemplates() as $template) {
            if ($state->checkTemplate($template)) {
                echo "got the template";
            } else {
                echo "not this template";
            }
        }

        return false;
    }
}
