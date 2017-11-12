<?php

use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeyFactory;

require __DIR__ . "/../vendor/autoload.php";

if ($argc < 2) {
    die("xpub required");
}

$xpub = HierarchicalKeyFactory::fromExtended($argv[1]);
$batchSize = 100;
$start = -$batchSize;
$history = [];

do {
    $start += $batchSize;
    $end = $start + $batchSize;

    echo "Scanning $start -> $end\n";
    $addrs = [];
    $utxoCount = 0;
    for ($i = $start; $i < $end; $i++) {
        $child = $xpub->deriveChild($i);
        $utxos = [];
        $n = count($utxos);
        if ($n > 0) {
            $addrs[] = [
                "index" => $i,
                "child" => $child,
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

