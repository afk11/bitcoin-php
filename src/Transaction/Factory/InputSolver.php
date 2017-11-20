<?php

namespace BitWasp\Bitcoin\Transaction\Factory;

use BitWasp\Bitcoin\Script\Interpreter\Checker;
use BitWasp\Bitcoin\Script\Interpreter\Interpreter;
use BitWasp\Bitcoin\Script\Interpreter\Stack;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Parser\Operation;
use BitWasp\Bitcoin\Script\ScriptInterface;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\PublicKey;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType\Signature;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\MatcherState;
use BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation\OperationInterface;

class InputSolver
{
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
     * @var Template[]
     */
    private $templates;

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
    const LEN20 = 0x14;

    const STR = [
        self::OP_SMALLINT => "smallint",
        self::OP_PUBKEY => "pubkey",
        self::OP_PUBKEYS => "pubkeys",
        self::OP_PUBKEYHASH => "pubkeyhash",
        self::OP_CHECKSIG => "checksig",
        self::OP_CHECKMULTISIG => "checkmultisig",
        self::OP_EQUAL => "equal",
        self::OP_INT32 => "int32",
    ];

    /**
     * TemplateMatcher constructor.
     * @param Checker $checker
     * @param bool[] $logicalPath
     */
    public function __construct(Checker $checker, array $logicalPath, array $templates = [])
    {
        $this->checker = $checker;
        $this->vfStack = new Stack();
        $this->interpreter = new Interpreter();
        $this->templates = $templates;
    }

    public static function testing(Checker $checker, array $logicalPath) {
        return new self($checker, $logicalPath, [
            new Template([new \BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation\CheckSig()]),
            new Template([new \BitWasp\Bitcoin\Transaction\Factory\Matcher\Operation\CheckSig()]),
        ]);
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

    /**
     * @param ScriptInterface $script
     * @return null
     */
    public function script(ScriptInterface $script)
    {
        $state = new MatcherState();
        $parser = $script->getScriptParser();

        $steps = [];
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
                echo "\nadd op\n";
                print_r($op);
                $state->withOperation($op);

                foreach ($this->templates as $i => $template) {
                    echo "Working template $i\n";
                    if ($template->matches($state)) {
                        echo "We have the template!\n";
                    }
                }
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
