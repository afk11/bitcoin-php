<?php
/**
 * Created by PhpStorm.
 * User: tk
 * Date: 11/18/17
 * Time: 5:18 PM
 */

namespace BitWasp\Bitcoin\Transaction\Factory\Matcher;


use BitWasp\Bitcoin\Script\Interpreter\Stack;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Parser\Operation;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation\OperationInterface;
use BitWasp\Bitcoin\Transaction\Factory\Template;
use BitWasp\Buffertools\BufferInterface;

class MatcherState
{
    private $ops = [];
    private $inputTypes = [];
    private $stack;

    public function __construct()
    {
        $this->stack = new Stack();
    }

    public function withOp(Operation $op) {
        array_unshift($this->ops, $op);
    }

    public function withData(BufferInterface $data) {
        $this->stack->push($data);
    }

    public function withOperation(Operation $operation) {
        if ($operation->isPush()) {
            $this->withData($operation->getData());
        } else {
            $this->withOp($operation);
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
        if ($tplOp instanceof InputType\PublicKey) {
            echo "   looking for public key\n";
            echo "   stackIdx " . (-$stackIdx-1).PHP_EOL;
            if (isset($stack[-$stackIdx-1])) {
                $size = $this->stack[-$stackIdx-1]->getSize();
                if ($size < 33 || $size > 65) {
                    return false;
                }
                $stackIdx++;
                //$values[] = $stack[-$stackIdx-1];
                return $tplOp;
            } else {
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
            if(!$this->checkTemplateStep($template)) {
                continue;
            }

            echo "!!! step succeeded, try next\n";
            return true;
        }

        return false;
    }
}
