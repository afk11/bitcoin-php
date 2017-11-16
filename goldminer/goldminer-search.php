<?php

use BitWasp\Bitcoin\Address\PayToPubKeyHashAddress;
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Key\Deterministic\ElectrumKeyFactory;
use BitWasp\Bitcoin\Key\PublicKeyFactory;
use BitWasp\Bitcoin\Network\NetworkFactory;
use GuzzleHttp\Client;

require __DIR__ . "/../vendor/autoload.php";

if ($argc < 2) {
    die("xpub required");
}

$input = $argv[1];
$btcg = NetworkFactory::create('26', '16', '80', false);
Bitcoin::setNetwork($btcg);

$mpk = "04" . $input;
$key = PublicKeyFactory::fromHex($mpk);
$xpub = ElectrumKeyFactory::fromKey($key);

$batchSize = 100;
$start = -$batchSize;
$history = [];

class PrivateClient {
    private $client;
    private $torControl;

    public function __construct($uri, $proxyUri, $controlHost, $controlPort, $controlPw)
    {
        $this->client = new Client([
            'base_uri' => $uri,
            'proxy' => $proxyUri
        ]);
        $this->torControl = new TorControl\TorControl(
            array(
                'hostname' => $controlHost,
                'port'     => $controlPort,
                'password' => $controlPw,
                'authmethod' => 1
            )
        );
        $this->torControl->connect();
        $this->torControl->authenticate();
    }

    public function newNym()
    {
        $res = $this->torControl->executeCommand('SIGNAL NEWNYM');
        var_dump($res);
        if ($res[0]['code'] !== "250") {
            throw new \RuntimeException("Failed to acquire new circuit");
        }
    }

    public function request($method, $uri, array $options = [])
    {
        return $this->client->request($method, $uri, $options);
    }
}

$client = new PrivateClient("https://btgexp.com/ext/", 'socks5://localhost:9050', "localhost", 9051, "testingpassword");
$client->newNym();

$res = $client->request('GET', '/ext/getaddress/GP4MnT7Xm4ahZhRcWFaqPGkZknMda1XuzA', ['verify' => false]);
$json = $res->getBody()->getContents();
do {
    $start += $batchSize;
    $end = $start + $batchSize;

    echo "Scanning $start -> $end\n";
    $addrs = [];
    $utxoCount = 0;
    for ($i = $start; $i < $end; $i++) {
        $client->newNym();
        $child = $xpub->deriveChild($i);
        $addr = new PayToPubKeyHashAddress($child->getPubKeyHash());
        echo $addr->getAddress().PHP_EOL;

        $res = $client->request('GET', 'getaddress/GP4MnT7Xm4ahZhRcWFaqPGkZknMda1XuzA', ['verify' => false]);
        $body = json_decode($res->getBody()->getContents(), true);
        print_r($body);
        die();
        $utxos = [];
        $n = count($utxos);
        if ($n > 0) {
            $addrs[] = [
                "index" => $i,
                "child" => $child->getAddress(),
                "utxos" => $utxos,
            ];
            $utxoCount += $n;
        }
    }

    $history[] = $utxoCount;
} while(count($history) < 3 || array_sum(array_slice($history, -3)) != 0);

echo json_encode($history, \JSON_PRETTY_PRINT).PHP_EOL;

///echo AddressFactory::fromKey($xpub->getPublicKey())->getAddress().PHP_EOL;
//echo $xpub->toExtendedKey().PHP_EOL;

