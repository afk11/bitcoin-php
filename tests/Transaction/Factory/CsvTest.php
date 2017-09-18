<?php

namespace BitWasp\Bitcoin\Tests\Transaction\Factory;

use BitWasp\Bitcoin\Address\AddressFactory;
use BitWasp\Bitcoin\Crypto\EcAdapter\Key\PrivateKeyInterface;
use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Script\Interpreter\Interpreter;
use BitWasp\Bitcoin\Script\Interpreter\Number;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\P2shScript;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\WitnessScript;
use BitWasp\Bitcoin\Tests\AbstractTestCase;
use BitWasp\Bitcoin\Transaction\Factory\SignData;
use BitWasp\Bitcoin\Transaction\Factory\Signer;
use BitWasp\Bitcoin\Transaction\Factory\TxBuilder;
use BitWasp\Bitcoin\Transaction\TransactionInput;
use BitWasp\Bitcoin\Transaction\TransactionInterface;
use BitWasp\Bitcoin\Transaction\TransactionOutput;

class CsvTest extends AbstractTestCase
{
    /**
     * @param int $locktime
     * @param int $sequence
     * @return TransactionInterface
     */
    public function txFixture($locktime, $sequence, $version = 2)
    {
        return (new TxBuilder())
            ->version($version)
            ->input('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234', 0, null, $sequence)
            ->output(90000000, AddressFactory::fromString("1BQLNJtMDKmMZ4PyqVFfRuBNvoGhjigBKF")->getScriptPubKey())
            ->locktime($locktime)
            ->get()
            ;
    }

    /**
     * @return array
     */
    public function getCltvCases()
    {
        $blocks100 = 100;
        $seconds100 = TransactionInput::SEQUENCE_LOCKTIME_TYPE_FLAG | 100;

        $errTxVersion = "Transaction version must be 2 or greater for CSV";
        $errCsvNotSeconds = "CSV was for timestamp, but txin sequence was in block range";
        $errCsvNotBlocks = "CSV was for block height, but txin sequence was in timestamp range";
        return [
            [
                $blocks100, $this->txFixture(0, $blocks100, 0), \RuntimeException::class, $errTxVersion,
            ],
            [
                $blocks100, $this->txFixture(0, $blocks100, 1), \RuntimeException::class, $errTxVersion,
            ],
            [
                $blocks100, $this->txFixture(0, $blocks100, 2), null, null,
            ],
            [
                $seconds100, $this->txFixture(0, $blocks100, 2), \RuntimeException::class, $errCsvNotSeconds,
            ],
            [
                $blocks100, $this->txFixture(0, $seconds100, 2), \RuntimeException::class, $errCsvNotBlocks,
            ],
        ];
    }

    /**
     * @param int $verifySequence
     * @param TransactionInterface $unsigned
     * @param null|string $exception
     * @param null|string $exceptionMsg
     * @dataProvider getCltvCases
     */
    public function testCsv($verifySequence, TransactionInterface $unsigned, $exception = null, $exceptionMsg = null)
    {
        /** @var PrivateKeyInterface[] $keys */
        $key = PrivateKeyFactory::fromHex("4200000042000000420000004200000042000000420000004200000042000000", true);

        $s = ScriptFactory::sequence([
            Number::int($verifySequence)->getBuffer(), Opcodes::OP_CHECKSEQUENCEVERIFY, Opcodes::OP_DROP,
            $key->getPublicKey()->getBuffer(), Opcodes::OP_CHECKSIG,
        ]);

        $ws = new WitnessScript($s);
        $rs = new P2shScript($ws);
        $spk = $rs->getOutputScript();

        $txOut = new TransactionOutput(100000000, $spk);

        $flags = Interpreter::VERIFY_DERSIG | Interpreter::VERIFY_P2SH | Interpreter::VERIFY_CHECKSEQUENCEVERIFY;

        $signData = (new SignData())
            ->p2sh($rs)
            ->p2wsh($ws)
            ->signaturePolicy($flags)
        ;

        $signer = (new Signer($unsigned))
            ->allowComplexScripts(true)
        ;

        if (null !== $exception) {
            $this->expectException($exception);
            $this->expectExceptionMessage($exceptionMsg);
        }

        $input = $signer
            ->input(0, $txOut, $signData)
            ->signStep(1, $key)
        ;

        if ($exception) {
            $this->fail("expected failure before verification can commence");
        }

        $this->assertTrue($input->verify());
    }
}
