<?php

namespace BitWasp\Bitcoin\Transaction\Factory;


use BitWasp\Bitcoin\Script\Interpreter\Stack;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Parser\Operation;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation\OperationInterface;
use BitWasp\Buffertools\BufferInterface;

class ResolverState
{
    /**
     * @var Stack
     *
     *
     */
    private $vfStack;

    /**
     * @var Stack
     */
    private $stack;

    /**
     * @var Operation[]
     */
    private $ops = [];

    /**
     * @var array
     */
    private $logicalPath;

    /**
     * @var BufferInterface[]
     */
    private $inputStack;

    public function __construct(array $logicalPath, array $inputStack)
    {
        $this->vfStack = new Stack();
        $this->stack = new Stack();
        $this->ops = [];
        $this->logicalPath = $logicalPath;
        $this->inputStack = $inputStack;
        $this->inputTypes = [];
    }

    public function vfStack() {
        return $this->vfStack;
    }

    public function stack() {
        return $this->stack;
    }

    public function withOperation(Operation $operation) {
        if ($operation->isPush()) {
            $this->stack->push($operation->getData());
        } else {
            array_unshift($this->ops, $operation);
        }
    }


    private function testOp($idx, $testOp, $stackIdx)
    {
        if ($testOp > Opcodes::OP_PUSHDATA4) {
            if (!isset($this->ops[$idx])) {
                return false;
            }
            $test = $testOp === $this->ops[$idx]->getOp();
            return $test;
        } else {
            if (!isset($this->stack[-$stackIdx-1])) {
                return false;
            }

            if ($testOp < Opcodes::OP_PUSHDATA1) {
                $test = $testOp === $this->stack[-$stackIdx-1]->getSize();
                return $test;
            } else {
                throw new \RuntimeException("Not implemented");
            }
        }
    }

    private function testTemplate($tplOp, &$stackIdx, &$opIdx)
    {
        if ($tplOp instanceof Matcher\InputType\FixedLengthBlob) {
            echo "looking for fixed length blob\n";
            if (isset($this->stack[-$stackIdx-1])) {
                $size = $this->stack[-$stackIdx-1]->getSize();
                if ($size === $tplOp->getLength()) {
                    $stackIdx++;
                    //$values[] = $stack[-$stackIdx-1];
                    return $tplOp;
                }
            } else {
                echo "notset\n";
            }
        } else if ($tplOp instanceof Matcher\InputType\PublicKey) {
            echo "   looking for public key\n";
            echo "   stackIdx " . (-$stackIdx-1).PHP_EOL;
            if (isset($this->stack[-$stackIdx-1])) {
                echo "wasset\n";
                $size = $this->stack[-$stackIdx-1]->getSize();
                if ($size < 33 || $size > 65) {
                    return false;
                }
                $stackIdx++;
                //$values[] = $stack[-$stackIdx-1];
                return $tplOp;
            }
        } else if (is_int($tplOp)) {
            echo "   looking for opcode: \n";
            echo "looking at index {$opIdx}\n";
            if (!$this->testOp($opIdx, $tplOp, $stackIdx)) {
                return false;
            }
            $opIdx++;
            return $tplOp;
        }

        return false;
    }

    private function checkTemplateStep(array $template) {
        $nOpTpl = count($template);
        echo __FUNCTION__.PHP_EOL;
        echo "   template has $nOpTpl items\n";
        // i is the pointer to $opTpl
        // j is the pointer to stack
        // k is the pointer to stack
        $stackIdx = 0;
        $opIdx = 0;

        for ($i = $nOpTpl-1; $i >= 0; $i--) {
            echo "   --2\n";
            $tplOp = $template[$i];
            echo "   tpl op $i\n";
            if ($this->testTemplate($tplOp, $stackIdx, $opIdx)) {
                echo "   gotit\n";
            } else {
                return false;
            }
        }

        return $template;
    }

    public function checkTemplate(OperationInterface $tpl) {
        $templates = $tpl->getTemplates();
        foreach ($templates as $i => $template) {
            echo "Testing segment $i\n";
            if (!$this->checkTemplateStep($template)) {
                continue;
            }

            echo "!!! step succeeded, try next\n";
            return true;
        }

        return false;
    }

    public function removeTemplateOps(OperationInterface $tpl) {
        $templates = $tpl->getTemplates();
        $templates = $templates[count($templates) - 1];

        do {
            $step = array_shift($templates);
            echo "CLEANUP\n";
            var_dump($step);
            if (is_int($step)) {
                echo "op:$step\n";
                array_pop($this->ops);
            } else {
                echo "pop from stack\n";
                $this->stack->pop();
            }
        } while(count($templates) > 0);
    }
}
