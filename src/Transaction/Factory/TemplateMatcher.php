<?php

namespace BitWasp\Bitcoin\Transaction\Factory;

use BitWasp\Bitcoin\Script\Interpreter\Checker;
use BitWasp\Bitcoin\Script\Interpreter\Interpreter;
use BitWasp\Bitcoin\Script\Interpreter\Stack;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Parser\Operation;
use BitWasp\Bitcoin\Script\ScriptInterface;

class TemplateMatcher
{
    private $templates = [
    ];

    /**
     * @var Operation[]
     */
    private $ops = [];

    /**
     * @var Interpreter
     */
    private $interpreter;

    /**
     * @var Stack
     */
    private $vfStack;

    /**
     * @var Stack
     */
    private $stack;

    /**
     * @var bool[]
     */
    private $logicalPath;

    /**
     * @var array|Checksig|Conditional|TimeLock
     */
    private $steps = [];

    const OP_SMALLINT = 0xff01;
    const OP_PUBKEY = 0xff02;
    const OP_PUBKEYS = 0xff03;
    const OP_PUBKEYHASH = 0xff04;
    const OP_CHECKSIG = 0xff05;
    const OP_CHECKMULTISIG = 0xff06;
    const OP_EQUAL = 0xff07;
    const OP_INT32 = 0xff08;
    const OP_SIG = 0xff09;
    const OP_SIGS = 0xff10;
    const LEN20 = 0x14;

    const STR = [
        self::OP_SMALLINT => "smallint",
        self::OP_PUBKEY => "pubkey",
        self::OP_PUBKEYS => "pubkeys",
        self::OP_PUBKEYHASH => "pubkeyhash",
        self::OP_CHECKSIG => "checksig",
        self::OP_CHECKMULTISIG => "checkmultisig",
        self::OP_SIG => "signature",
        self::OP_SIGS => "signatures",
        self::OP_EQUAL => "equal",
        self::OP_INT32 => "int32",
    ];

    /**
     * TemplateMatcher constructor.
     * @param Checker $checker
     * @param bool[] $logicalPath
     */
    public function __construct(Checker $checker, array $logicalPath)
    {
        $this->interpreter = new Interpreter();
        $this->vfStack = new Stack();
        $this->stack = new Stack();
        $this->logicalPath = $logicalPath;
        $this->templates = [
            //['p2pk', [], [self::OP_PUBKEY, Opcodes::OP_CHECKSIG]],
            ['p2pk', [self::OP_SIG], [self::OP_PUBKEY, self::OP_CHECKSIG]],
            ['hashlock160', [], [Opcodes::OP_HASH160, self::LEN20, self::OP_EQUAL]],
//            ['multisig', [], [self::OP_SMALLINT, self::OP_PUBKEYS, self::OP_SMALLINT, self::OP_CHECKMULTISIG]],
//            ['cltv', [], [self::OP_INT32, Opcodes::OP_DROP, Opcodes::OP_CHECKLOCKTIMEVERIFY]],
        ];
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

    private function testOp(Stack $stack, $idx, $testOp, $stackIdx)
    {
        if ($testOp > Opcodes::OP_PUSHDATA4) {
            if (!isset($this->ops[$idx])) {
                return false;
            }
            $test = $testOp === $this->ops[$idx]->getOp();
            return $test;
        } else {
            if (!isset($stack[-$stackIdx-1])) {
                return false;
            }

            if ($testOp < Opcodes::OP_PUSHDATA1) {
                $test = $testOp === $stack[-$stackIdx-1]->getSize();
                return $test;
            } else {
                throw new \RuntimeException("Not implemented");
            }
        }
    }

    private function testTemplate($tplOp, Stack $stack, &$stackIdx, &$opIdx)
    {
        if ($tplOp === self::OP_PUBKEYS) {
            while ($stackIdx < $stack->count()+1 && $stack[-$stackIdx]->getSize() >= 33 && $stack[-$stackIdx]->getSize() <= 65) {
                echo "j=$stackIdx";
                $stackIdx++;
            }
            return true;
        } else if ($tplOp === self::OP_SMALLINT) {
            if ($stack[-$stackIdx-1]->getSize() === 1) {
                $int = (int) $stack[-$stackIdx-1]->getInt();
                if ($int < 0 || $int > 16) {
                    return false;
                }
                $values[] = $stack[-$stackIdx-1];
                $stackIdx++;
                return true;
            }
        } else if ($tplOp === self::OP_PUBKEY) {
            echo "check pubkey\n";
            if (isset($stack[-$stackIdx-1])) {
                echo "wasset\n";
                echo "val: {$stack[-$stackIdx-1]->getHex()}\n";
                $size = $stack[-$stackIdx-1]->getSize();
                if ($size < 33 || $size > 65) {
                    return false;
                }
                $stackIdx++;
                //$values[] = $stack[-$stackIdx-1];
                return true;
            } else {
                echo "notfound: {$stackIdx}\n";
            }
        } else if ($tplOp === self::OP_INT32) {
            if (isset($stack[-$stackIdx-1])) {
                $size = $stack[-$stackIdx-1]->getSize();
                if ($size > 5) {
                    return false;
                }
                $stackIdx++;
                return true;
            }
        } else if ($tplOp === self::OP_CHECKSIG) {
            if (!($this->testOp($stack, $opIdx, Opcodes::OP_CHECKSIGVERIFY, $stackIdx) || $this->testOp($stack, $opIdx, Opcodes::OP_CHECKSIG, $stackIdx))) {
                return false;
            }
            $opIdx++;
            return true;
        } else if ($tplOp === self::OP_CHECKMULTISIG) {
            if (!($this->testOp($stack, $opIdx, Opcodes::OP_CHECKMULTISIGVERIFY, $stackIdx) || $this->testOp($stack, $opIdx, Opcodes::OP_CHECKMULTISIG, $stackIdx))) {
                return false;
            }
            $opIdx++;
            return true;
        } else if ($tplOp === self::OP_EQUAL) {
            if (!($this->testOp($stack, $opIdx, Opcodes::OP_EQUAL, $stackIdx) || $this->testOp($stack, $opIdx, Opcodes::OP_EQUALVERIFY, $stackIdx))) {
                return false;
            }
            $opIdx++;
            return true;
        } else {
            throw new \RuntimeException("Unknown template: $tplOp");
        }

        return false;
    }

    private function checkTemplates(Stack $stack)
    {
        foreach ($this->templates as $template) {
            echo "\n";
            echo "--1\n";
            list ($tpl, $stack2Match, $opTpl) = $template;
            echo "checking for template: $tpl\n";

            $countStack = count($stack);
            $nOpTpl = count($opTpl);

            // i is the pointer to $opTpl
            // j is the pointer to stack
            // k is the pointer to stack
            $stackIdx = 0;
            $opIdx = 0;
            for ($i = $nOpTpl-1; $i >= 0; $i--) {
                echo "--2\n";
                $tplOp = $opTpl[$i];
                $tplType = $tplOp & 0xff00;

                if ($tplType === 0) {
                    echo "testing opcode {$tplOp}\n";
                    if (!$this->testOp($stack, $opIdx, $tplOp, $stackIdx)) {
                        echo "notop {$tplOp}, abort\n";
                        continue 2;
                    }

                    echo "op, succeed\n";
                } else if ($tplType === 0xff00) {
                    $s = array_key_exists($tplOp, self::STR) ? self::STR[$tplOp] : '';
                    echo "testing template {$tplOp} {$s}\n";
                    if (!$this->testTemplate($tplOp, $stack, $stackIdx, $opIdx)) {
                        echo "nottemplate {$tplOp}\n";
                        continue 2;
                    }
                } else {
                    throw new \RuntimeException("Bad template");
                }
            }

            echo "finished\n";
            return $template;
        }

        return null;
    }

    /**
     * @param ScriptInterface $script
     * @return null
     */
    public function script(ScriptInterface $script)
    {
        $parser = $script->getScriptParser();
        foreach ($parser->decode() as $op) {
            $fExec = !$this->interpreter->checkExec($this->vfStack, false);

            if ($op->isLogical()) {
                switch ($op->getOp()) {
                    case Opcodes::OP_IF:
                    case Opcodes::OP_NOTIF:
                        $value = false;
                        if ($fExec) {
                            // Pop from mainStack if $fExec
                            $step = $this->extractConditionalOp($op, $this->stack, $pathCopy);

                            // the Conditional has a value in this case:
                            $value = $step->getValue();

                            // Connect the last operation (if there is one)
                            // with the last step with isRequired==$value
                            // todo: check this part out..
                            for ($j = count($this->steps) - 1; $j >= 0; $j--) {
                                if ($this->steps[$j] instanceof Checksig && $value === $this->steps[$j]->isRequired()) {
                                    $step->providedBy($this->steps[$j]);
                                    break;
                                }
                            }
                        } else {
                            $step = new Conditional($op->getOp());
                        }

                        $this->steps[] = $step;

                        if ($op->getOp() === Opcodes::OP_NOTIF) {
                            $value = !$value;
                        }

                        $this->vfStack->push($value);
                        return $step;

                    case Opcodes::OP_ENDIF:
                        $this->vfStack->pop();
                        break;
                    case Opcodes::OP_ELSE:
                        $this->vfStack->push(!$this->vfStack->pop());
                        break;
                }

                return null;
            }

            if ($fExec) {
                if ($op->isPush()) {
                    echo "\n\npush: {$op->getData()->getHex()}\n";
                    $this->stack->push($op->getData());
                } else {
                    echo "\n\nop: {$op->getOp()}\n";
                    array_unshift($this->ops, $op);
                    //$this->ops[] = $op;
                }

                $template = $this->checkTemplates($this->stack);

                if (!$op->isPush()) {
                    switch ($op->getOp()) {
                        case Opcodes::OP_CHECKSIG:
                        case Opcodes::OP_CHECKSIGVERIFY:
                            break;
                        default:
                            throw new \RuntimeException("Not implemented");
                    }
                }

                echo "chk template: " . ($template === null ?'null': "have template: " . $template[0]) . PHP_EOL;
            }
        }
    }

    /**/
    public function __debugInfo()
    {
        return [
            'ops' => $this->ops,
            'stack' => $this->stack,
        ];
    }
    /**/
}
