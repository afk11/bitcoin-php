<?php

namespace BitWasp\Bitcoin\RpcTest;

use BitWasp\Bitcoin\Network\NetworkInterface;
use BitWasp\Bitcoin\Script\Interpreter\Interpreter;

abstract class AbstractTestCase extends \PHPUnit_Framework_TestCase
{
    /**
     * @var array
     */
    private $scriptFlagNames;

    /**
     * @var NetworkInterface
     */
    protected $network;

    /**
     * AbstractTestCase constructor.
     * @param null $name
     * @param array $data
     * @param string $dataName
     */
    public function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
    }

    /**
     * @param string $name
     * @return array
     */
    public function jsonDataFile($name)
    {
        $contents = $this->dataFile($name);
        $decoded = json_decode($contents, true);
        if (false === $decoded || json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Invalid JSON file ' . $name);
        }

        return $decoded;
    }

    /**
     * @param string $filename
     * @return string
     */
    public function dataFile($filename)
    {
        $contents = file_get_contents($this->dataPath($filename));
        if (false === $contents) {
            throw new \RuntimeException('Failed to data file ' . $filename);
        }
        return $contents;
    }

    /**
     * @param string $file
     * @return string
     */
    public function dataPath($file)
    {
        return __DIR__ . '/../tests/Data/' . $file;
    }


    /**
     * @return array
     */
    public function calcMapScriptFlags()
    {
        if (null === $this->scriptFlagNames) {
            $this->scriptFlagNames = [
                "NONE" => Interpreter::VERIFY_NONE,
                "P2SH" => Interpreter::VERIFY_P2SH,
                "STRICTENC" => Interpreter::VERIFY_STRICTENC,
                "DERSIG" => Interpreter::VERIFY_DERSIG,
                "LOW_S" => Interpreter::VERIFY_LOW_S,
                "SIGPUSHONLY" => Interpreter::VERIFY_SIGPUSHONLY,
                "MINIMALDATA" => Interpreter::VERIFY_MINIMALDATA,
                "NULLDUMMY" => Interpreter::VERIFY_NULL_DUMMY,
                "DISCOURAGE_UPGRADABLE_NOPS" => Interpreter::VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
                "CLEANSTACK" => Interpreter::VERIFY_CLEAN_STACK,
                "CHECKLOCKTIMEVERIFY" => Interpreter::VERIFY_CHECKLOCKTIMEVERIFY,
                "CHECKSEQUENCEVERIFY" => Interpreter::VERIFY_CHECKSEQUENCEVERIFY,
                "WITNESS" => Interpreter::VERIFY_WITNESS,
                "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => Interpreter::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
                "MINIMALIF" => Interpreter::VERIFY_MINIMALIF,
                "NULLFAIL" => Interpreter::VERIFY_NULLFAIL,
            ];
        }

        return $this->scriptFlagNames;
    }

    /**
     * @param string $string
     * @return int
     */
    public function getScriptFlagsFromString($string)
    {
        $mapFlagNames = $this->calcMapScriptFlags();
        if (strlen($string) === 0) {
            return Interpreter::VERIFY_NONE;
        }

        $flags = 0;
        $words = explode(",", $string);
        foreach ($words as $word) {
            if (!isset($mapFlagNames[$word])) {
                throw new \RuntimeException('Unknown verification flag: ' . $word);
            }

            $flags |= $mapFlagNames[$word];
        }

        return $flags;
    }

    protected function assertRpcNoError($result) {
        $this->assertInternalType('array', $result);
        $this->assertArrayHasKey('error', $result);
        $this->assertEquals(null, $result['error']);
    }

    protected function assertRpcSubmitBlock($result) {
        $this->assertRpcNoError($result);
        $this->assertArrayHasKey('result', $result);
        $this->assertNull($result['result'], "block submission should succeed");
    }

    protected function assertRpcSendRawTx($result) {
        $this->assertRpcNoError($result);

        $this->assertArrayHasKey('result', $result);
        $this->assertEquals(64, strlen($result['result']));
    }

    protected function assertRpcGetBestBlockHash($result) {
        $this->assertRpcNoError($result);

        $this->assertArrayHasKey('result', $result);
        $this->assertEquals(64, strlen($result['result']));
    }

    protected function assertRpcGetBlock($result) {
        $this->assertRpcNoError($result);

        $this->assertArrayHasKey('result', $result);
        $this->assertInternalType('array', $result['result']);
        $this->assertArrayHasKey('height', $result['result']);
        $this->assertArrayHasKey('hash', $result['result']);
        $this->assertArrayHasKey('version', $result['result']);
        $this->assertArrayHasKey('previousblockhash', $result['result']);
        $this->assertArrayHasKey('merkleroot', $result['result']);
        $this->assertArrayHasKey('bits', $result['result']);
        $this->assertArrayHasKey('time', $result['result']);
        $this->assertArrayHasKey('nonce', $result['result']);

    }

    protected function assertBitcoindError($errorCode, $result)
    {
        $this->assertInternalType('array', $result);
        $this->assertArrayHasKey('error', $result);
        $this->assertInternalType('array', $result['error']);
        $this->assertEquals($errorCode, $result['error']['code']);

        $this->assertArrayHasKey('error', $result);
        $this->assertEquals(null, $result['result']);
    }

}
