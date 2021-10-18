<?php
require_once '../vendor/autoload.php';
require_once '../src/OIDCClient.php';

use Maicol07\OIDCClient\OIDCClient;

$client = new OIDCClient([
    'client_id' => '000123',
    'client_secret' => 'rlC_8s3oBayCynAO_7UKt34hbEwiiTKx0l7zRcrFY3A',
    'provider_url' => 'https://demo.c2id.com',
    //'redirect_uri' => 'https://demo.c2id.com/oidc-client/cb',
    'jwt_plain_key' => true
]);
$client->authenticate();
