<?php

namespace BitWasp\Bitcoin\RpcTest;


use BitWasp\Bitcoin\Address\AddressFactory;
use BitWasp\Bitcoin\Address\AddressInterface;
use BitWasp\Bitcoin\Key\PublicKeyFactory;
use BitWasp\Bitcoin\Network\NetworkFactory;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptInterface;

class ScriptSortingTest extends AbstractTestCase
{
    /**
     * @param int $m
     * @param string[] $keys
     * @param bool $sort
     * @return array
     */
    public function sortingTestCase($m, array $keys, $sort, AddressInterface $addr = null) {
        return [
            $m,
            $keys,
            $sort,
            ScriptFactory::scriptPubKey()->multisig($m, array_map([PublicKeyFactory::class, 'fromHex'], $keys), $sort),
            $addr instanceof AddressInterface ? $addr->getAddress($this->network) : null,
        ];
    }

    public function getSortingProvider() {
        $disableRpcSort = !!json_decode(getenv("DISABLE_RPC_SORT_TEST"));
        if ($disableRpcSort) {
            fwrite(STDERR, <<<TEXT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Skipping multisig key sorting tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


TEXT
            );

            return [];
        }

        $key1A = "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8";
        $key1B = "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f";

        $key2A = "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0";
        $key2B = "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77";
        $key2C = "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404";

        $key3A = "030000000000000000000000000000000000004141414141414141414141414141";
        $key3B = "020000000000000000000000000000000000004141414141414141414141414141";
        $key3C = "020000000000000000000000000000000000004141414141414141414141414140";
        $key3D = "030000000000000000000000000000000000004141414141414141414141414140";

        $key4A = "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da";
        $key4B = "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9";
        $key4C = "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18";

        $mainnet = NetworkFactory::bitcoin();
        $addr1Sorted = AddressFactory::fromString("39bgKC7RFbpoCRbtD5KEdkYKtNyhpsNa3Z", $mainnet);
        $addr2Sorted = AddressFactory::fromString("3CKHTjBKxCARLzwABMu9yD85kvtm7WnMfH", $mainnet);
        $addr3Sorted = AddressFactory::fromString("32V85igBri9zcfBRVupVvwK18NFtS37FuD", $mainnet);
        $addr4Sorted = AddressFactory::fromString("3Q4sF6tv9wsdqu2NtARzNCpQgwifm2rAba", $mainnet);

        return [
            // set 1
            // true order is B, A
            // these are already in order
            $this->sortingTestCase(2, [$key1B, $key1A], false, $addr1Sorted),
            $this->sortingTestCase(2, [$key1B, $key1A], true, $addr1Sorted),

            // out of order but sorted
            $this->sortingTestCase(2, [$key1A, $key1B], true, $addr1Sorted),

            // out of order, not sorted
            $this->sortingTestCase(2, [$key1A, $key1B], false),

            // set 2
            // true order is A, B, C
            // these are already in order
            $this->sortingTestCase(2, [$key2A, $key2B, $key2C], true, $addr2Sorted),
            $this->sortingTestCase(2, [$key2A, $key2B, $key2C], false, $addr2Sorted),

            // out of order but sorted
            $this->sortingTestCase(2, [$key2B, $key2A, $key2C], true, $addr2Sorted),
            $this->sortingTestCase(2, [$key2B, $key2C, $key2A], true, $addr2Sorted),
            $this->sortingTestCase(2, [$key2C, $key2A, $key2B], true, $addr2Sorted),
            $this->sortingTestCase(2, [$key2C, $key2B, $key2A], true, $addr2Sorted),
            $this->sortingTestCase(2, [$key2A, $key2C, $key2B], true, $addr2Sorted),

            // out of order, not sorted
            $this->sortingTestCase(2, [$key2B, $key2A, $key2C], false),
            $this->sortingTestCase(2, [$key2B, $key2C, $key2A], false),
            $this->sortingTestCase(2, [$key2C, $key2A, $key2B], false),
            $this->sortingTestCase(2, [$key2C, $key2B, $key2A], false),
            $this->sortingTestCase(2, [$key2A, $key2C, $key2B], false),

            // set 3
            // true order is C B D A
            $this->sortingTestCase(2, [$key3C, $key3B, $key3D, $key3A], true, $addr3Sorted),
            $this->sortingTestCase(2, [$key3C, $key3B, $key3D, $key3A], false, $addr3Sorted),

            // out of order but sorted
            $this->sortingTestCase(2, [$key3B, $key3A, $key3C, $key3D], true, $addr3Sorted),
            $this->sortingTestCase(2, [$key3B, $key3C, $key3A, $key3D], true, $addr3Sorted),
            $this->sortingTestCase(2, [$key3C, $key3A, $key3B, $key3D], true, $addr3Sorted),
            $this->sortingTestCase(2, [$key3C, $key3B, $key3A, $key3D], true, $addr3Sorted),
            $this->sortingTestCase(2, [$key3A, $key3C, $key3B, $key3D], true, $addr3Sorted),

            // out of order, not sorted
            $this->sortingTestCase(2, [$key3A, $key3B, $key3C, $key3D], false),
            $this->sortingTestCase(2, [$key3A, $key3B, $key3D, $key3C], false),
            $this->sortingTestCase(2, [$key3A, $key3C, $key3B, $key3D], false),
            $this->sortingTestCase(2, [$key3A, $key3C, $key3D, $key3B], false),
            $this->sortingTestCase(2, [$key3A, $key3D, $key3B, $key3C], false),
            $this->sortingTestCase(2, [$key3A, $key3D, $key3C, $key3B], false),

            // set 4
            // true order is B A C
            $this->sortingTestCase(2, [$key4C, $key4A, $key4B], false, $addr4Sorted),
            $this->sortingTestCase(2, [$key4C, $key4A, $key4B], true, $addr4Sorted),

            // out of order but sorted
            $this->sortingTestCase(2, [$key4B, $key4C, $key4A], true, $addr4Sorted),
            $this->sortingTestCase(2, [$key4C, $key4A, $key4B], true, $addr4Sorted),
            $this->sortingTestCase(2, [$key4C, $key4B, $key4A], true, $addr4Sorted),
            $this->sortingTestCase(2, [$key4A, $key4C, $key4B], true, $addr4Sorted),
            $this->sortingTestCase(2, [$key4A, $key4B, $key4C], true, $addr4Sorted),

            $this->sortingTestCase(2, [$key4B, $key4C, $key4A], false),
            $this->sortingTestCase(2, [$key4C, $key4A, $key4B], false),
            $this->sortingTestCase(2, [$key4C, $key4B, $key4A], false),
            $this->sortingTestCase(2, [$key4A, $key4C, $key4B], false),
            $this->sortingTestCase(2, [$key4A, $key4B, $key4C], false),
        ];
    }

    /**
     * @param $m
     * @param array $keys
     * @param $fSort
     * @param ScriptInterface $ourScript
     * @dataProvider getSortingProvider
     */
    public function testSortingAgainstRpc($m, array $keys, $fSort, ScriptInterface $ourScript, $address) {
        $result = $this->makeRpcRequest('createmultisig', [$m, $keys, ["sort"=>$fSort]]);

        if ($result['error'] !== null) {
            throw new \RuntimeException($result['error']['message'], $result['error']['code']);
        }

        $this->assertEquals($ourScript->getHex(), $result['result']['redeemScript']);
        if ($address) {
            $this->assertEquals($address, $result['result']['address']);
        }
    }

    public function testDefault()
    {
        $key2A = "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0";
        $key2B = "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77";
        $key2C = "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404";

        $sorted = AddressFactory::fromString("3CKHTjBKxCARLzwABMu9yD85kvtm7WnMfH", NetworkFactory::bitcoin())->getAddress($this->network);

        $resultABC = $this->makeRpcRequest('createmultisig', [2, [$key2A, $key2B, $key2C]]);
        $this->assertEquals($sorted, $resultABC['result']['address']);

        $resultBAC = $this->makeRpcRequest('createmultisig', [2, [$key2B, $key2A, $key2C]]);
        $this->assertNotEquals($sorted, $resultBAC['result']['address']);

        $resultCAB = $this->makeRpcRequest('createmultisig', [2, [$key2C, $key2A, $key2B]]);
        $this->assertNotEquals($sorted, $resultCAB['result']['address']);

        $resultCBA = $this->makeRpcRequest('createmultisig', [2, [$key2C, $key2B, $key2A]]);
        $this->assertNotEquals($sorted, $resultCBA['result']['address']);
    }

    public function testRejectsCompressedKeys()
    {
        $keyA = "02fdf7e1b65a477a7815effde996a03a7d94cbc46f7d14c05ef38425156fc92e22";
        $keyB = "04823336da95f0b4cf745839dff26992cef239ad2f08f494e5b57c209e4f3602d5526bc251d480e3284d129f736441560e17f3a7eb7ed665fdf0158f44550b926c";

        $oldAllowedRedeemScript = "522102fdf7e1b65a477a7815effde996a03a7d94cbc46f7d14c05ef38425156fc92e224104823336da95f0b4cf745839dff26992cef239ad2f08f494e5b57c209e4f3602d5526bc251d480e3284d129f736441560e17f3a7eb7ed665fdf0158f44550b926c52ae";

        $this->checkLegacyScriptsAreUnsupported(2, [$keyA, $keyB], $oldAllowedRedeemScript);
    }

    public function testHash160WillCheckWallet()
    {
        $keyA = "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0";
        $keyB = "04dd4fe618a8ad14732f8172fe7c9c5e76dd18c2cc501ef7f86e0f4e285ca8b8b32d93df2f4323ebb02640fa6b975b2e63ab3c9d6979bc291193841332442cc6ad";

        $oldAllowedRedeemScript = "522102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed04104dd4fe618a8ad14732f8172fe7c9c5e76dd18c2cc501ef7f86e0f4e285ca8b8b32d93df2f4323ebb02640fa6b975b2e63ab3c9d6979bc291193841332442cc6ad52ae";

        $this->makeRpcRequest('importpubkey', [$keyA]);
        $this->makeRpcRequest('importpubkey', [$keyB]);

        $pkA = PublicKeyFactory::fromHex($keyA);
        $pkB = PublicKeyFactory::fromHex($keyB);

        $addrA = AddressFactory::fromKey($pkA)->getAddress($this->network);
        $addrB = AddressFactory::fromKey($pkB)->getAddress($this->network);

        $this->checkLegacyScriptsAreUnsupported(2, [$addrA, $addrB], $oldAllowedRedeemScript);
    }

    public function checkLegacyScriptsAreUnsupported($m, array $keyInput, $oldAllowedRedeemScript)
    {
        $result = $this->makeRpcRequest('createmultisig', [2, $keyInput]);
        $this->assertEquals(null, $result['error'], "should not receive an error");
        $this->assertEquals($oldAllowedRedeemScript, $result['result']['redeemScript']);

        $result = $this->makeRpcRequest('createmultisig', [2, $keyInput, ["sort" => false]]);
        $this->assertEquals(null, $result['error'], "should not receive an error");
        $this->assertEquals($oldAllowedRedeemScript, $result['result']['redeemScript']);

        $result = $this->makeRpcRequest('createmultisig', [2, $keyInput, ["sort" => true]]);
        $this->assertNotEquals(null, $result['error'], "should receive an error");
        $this->assertInternalType('array', $result['error']);
        $this->assertArrayHasKey('message', $result['error']);
        $this->assertContains('Compressed key required', $result['error']['message']);
    }
}
