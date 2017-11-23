<?php

namespace BitWasp\Bitcoin\Transaction\Factory;


use BitWasp\Bitcoin\Script\Interpreter\Stack;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Parser\Operation;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\DataBlob;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\FixedLengthBlob;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\PublicKey;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\Signature;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation\OperationInterface;
use BitWasp\Buffertools\BufferInterface;
use Psr\Log\InvalidArgumentException;

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
    /**
     * @var array
     */
    private $valTypes;

    public function __construct(array $logicalPath, array $inputStack)
    {
        $this->vfStack = new Stack();
        $this->stack = new Stack();
        $this->ops = [];
        $this->logicalPath = $logicalPath;
        $this->inputStack = $inputStack;
        $this->valTypes = new Stack();
    }

    public function vfStack() {
        return $this->vfStack;
    }

    public function stack() {
        return $this->stack;
    }

    private function mutateType($idx, $toType, $length = null) {
        $val = $this->valTypes[$idx];
        $newType = null;

        if ($val instanceof DataBlob) {
            if (PublicKey::class === $toType) {
                $newType = new PublicKey();
            } else if (Signature::class === $toType) {
                $newType = new Signature();
            } else if (FixedLengthBlob::class === $toType) {
                if (!$length) {
                    throw new InvalidArgumentException();
                }
                $newType = new FixedLengthBlob($length);
            }
        }

        if (null === $newType) {
            throw new \RuntimeException("Failed to mutate type");
        }

        $valTypes = new Stack();
        foreach ($this->valTypes->all() as $i => $valType) {
            if (spl_object_hash($val) === spl_object_hash($valType)) {
                echo "replacing $i, " . get_class($val) . " with $toType\n";
                $valTypes->push($newType);
            } else {
                $valTypes->push($valType);
            }
        }

        $this->valTypes = $valTypes;
    }

    private $created = [];
    public function readValue($idx, $type, $length = null) {
        if (isset($this->valTypes[$idx])) {
            if (get_class($this->valTypes[$idx]) !== $type) {
                echo "read type, but didn't match, try to mutate\n";
                echo get_class($this->valTypes[$idx]).PHP_EOL;
                echo $type.PHP_EOL;
                if (($parent = get_parent_class($this->valTypes[$idx]))) {
                    echo "parent: $parent\n";
                    if ($parent === $type) {
                        return $this->valTypes[$idx];
                    }
                }

                echo "MUTATE BEGIN\n";
                $this->debugTypes();
                $this->mutateType($idx, $type, $length);
                $this->debugTypes();
                echo "MUTATE END\n";
            }
            return $this->valTypes[$idx];
        }

        switch ($type) {
            case DataBlob::class:
                $type = new DataBlob();
                $this->valTypes->push($type);
                break;
            case FixedLengthBlob::class:
                if (!$length) {
                    throw new InvalidArgumentException();
                }
                $type = new FixedLengthBlob($length);
                $this->valTypes->push($type);
                break;
            case PublicKey::class:
                $this->valTypes->push(new PublicKey());
                break;
            case Signature::class:
                $this->valTypes->push(new Signature());
                break;
            default:
                throw new InvalidArgumentException("Unsupported type");
        }

        $this->created[] = $this->valTypes[$idx];
        return $type;
    }

    public function addsValue($idx) {

    }

    public function consumeValue($idx, $type) {
        $this->readValue($idx, $type);
        unset($this->valTypes[$idx]);
        return $type;
    }

    public function debugTypes() {
        echo "types\n";
        foreach ($this->valTypes as $type) {
            echo " * " . get_class($type).PHP_EOL;
        }
        echo PHP_EOL;
        echo "created\n";
        foreach ($this->created as $type) {
            echo " * " . get_class($type).PHP_EOL;
        }
        echo PHP_EOL;
    }

    public function addElement($element) {
        switch (get_class($element)) {
            case DataBlob::class:
            case FixedLengthBlob::class:
                break;
            default:
                throw new \RuntimeException("Unknown element type");
        }

        $this->valTypes->push($element);
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
