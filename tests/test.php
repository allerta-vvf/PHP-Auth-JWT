<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

/*
 * WARNING:
 *
 * Do *not* use these files from the `tests` directory as the foundation
 * for the usage of this library in your own code. Instead, please follow
 * the `README.md` file in the root directory of this project.
 */

// enable error reporting
\error_reporting(\E_ALL);
\ini_set('display_errors', 'stdout');
\header('Content-type: text/html; charset=utf-8');

require __DIR__.'/../vendor/autoload.php';

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;

$db = new \PDO('mysql:dbname=php_auth;host=127.0.0.1;charset=utf8mb4', 'root', '');
// or
// $db = new \PDO('pgsql:dbname=php_auth;host=127.0.0.1;port=5432', 'postgres', 'monkey');
// or
// $db = new \PDO('sqlite:../Databases/php_auth.sqlite');

/*
$JWTconfig = Configuration::forAsymmetricSigner(
    // You may use RSA or ECDSA and all their variations (256, 384, and 512) and EdDSA over Curve25519
    new Signer\Rsa\Sha256(),
    InMemory::file(__DIR__ . '/private.pem'),
    InMemory::file(__DIR__ . '/public.pem'),
    // You may also override the JOSE encoder/decoder if needed by providing extra arguments here
);
*/
$JWTconfig = Configuration::forAsymmetricSigner(
    new Signer\Rsa\Sha256(),
    InMemory::base64Encoded('LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRRFR2d0U4N010Z1JFWUwKVEw0YUhoUW8zWnpvZ214eHZNVXNLblB6eXhSczFZclhPU09wd04wbnBzWGFyQktLVklVTU5MZkZPRHAvdm5RbgoyWnAwNk44WEc1OVdBT0t3dkM0TWZ4TERRa0ErSlhnZ3pIbGtiVm9UTitkVWtkWUlGcVNLdUFQR3dpV1RvUksyClN4RWhpajNyRTJGT044alFadkR4WmtpUDlhNHZ4Sk8zT1RQUXdLcmVkWEZpT2JzWEQvYzNSdExGaEtjdGpDeUgKT0lyUDBiUUVzZWUvbTdKTnRHNHJ5NkJQdXNONndiK3ZKbzVpZUJZUGEzYzE5YWtOcTZxL25ZV2hwbGhra0pTdQphT3JMNXhYRUZ6STVUdmN2blhSNTY4R1ZjeEs4WUxmRmtkeHBzWEd0NXJBYmVoMGgvVTVrSUxFQXF2OFA5UEdUClpwaWNLYnJuQWdNQkFBRUNnZ0VBZDN5VFFFUUhSOTEvQVNWZktQSE1RbnM3N2VDYlBWdGVrRnVzYnVnc01IWVkKRVBkSGJxVk1wdkZ2T01SYytmNVR6ZDE1emlxNnFCZGJDSm04bFRoTG00aVUwejFRcnBhaURaOHZnVXZEWU01WQpDWG9aRGxpK3VaV1VUcDYwL245NGZtYjBpcFpJQ2hTY3NJMlByek9KV1R2b2J2RC91c284TUp5ZFdjOHphZlFtCnVxWXp5Z09makZadlU0bFNmZ3pwZWZocHF1eTBKVXk1VGlLUm1HVW53TGIzVHRjc1ZhdmpzbjRRbU53TFlnT0YKMk9FK1IxMmV4M3BBS1RpUkU2RmNuRTF4RklvMUdLaEJhMk90Z3czTURPNkdnK2tuOFE0YWxLejZDNlJSbGdhSApSN3NZekVmSmhzay9HR0ZUWU96WEtRejJsU2FTdEt0OXdLQ29yMDRSY1FLQmdRRHpQT3U1akNUZmF5VW83eFkyCmpIdGlvZ0h5S0xMT2J0OWwzcWJ3Z1huYUQ2cm54WU52Q3JBME9NdlQraVpYc0ZaS0prWXpKcjhaT3hPcFBST2sKMTBXZE9hZWZpd1V5TDVkeXB1ZVN3bElEd1ZtK2hJNEJzODJNYWpIdHpPb3poKzczd0ErYXc1clBzODRVaXg5dwpWYmJ3YVZSNnFQL0JWMDl5SllTNWtRN2Ztd0tCZ1FEZTJ4anl3WDJkMk1DK3F6UnIrTGZVKzErZ3EwampoQkNYCldIcVJONklFQ0IweFRuWFVmOVdML1ZDb0kxLzU1QmhkYmJFamErNGJ0WWdjWFNQbWxYQklSS1E0VnRGZlZtWUIKa1BYZUQ4b1o3THl1TmRDc2JLTmUreDFJSFhEZTZXZnMzTDl1bENmWHhlSUU4NHd5M2ZkNjZtUWFoeVhWOWlEOQpDa3VpZk1xVXBRS0JnUUNpeWRIbFkxTEdKL285dEEyRXdtNU5hNm1ydk9zMlYyT3gxTnFiT2J3b1liWDYyZWlGCjUzeFg1dThiVmw1VTc1SkFtKzc5aXQvNGJkNVJ0S3V4OWRVRVRiTE9od2NhT0ZtK2hNK1ZHL0l4eXpSWjJuTUQKMXFjcFkyVTVCcHh6a25VdllGM1JNVG9wNmVkeFBrN3pLcHA5dWJDdFN1K29JTnZ0eEFoWS9Ta2NJd0tCZ0dQMQp1cGNJbXlPMkdaNXNoTEw1ZU51YmRTVklMd1YrTTBMdmVPcXlIWVhaYmQ2ejVyNU9LS2NHRkt1V1VuSndFVTIyCjZnR05ZOXdoN005c0o3SkJ6WDljNnB3cXRQY2lkZGEyQXRKOEdwYk9UVU9HOS9hZk5CaGlZcHY2T0txRDN3MnIKWm1KZktnL3F2cHFoODN6TmV6Z3k4bnZEcXdEeHlaSTJqLzV1SXgvUkFvR0JBTVdSbXh0djZIMmNLaGliSS9hSQpNVEpNNFFSanlQTnhRcXZBUXN2K29IVWJpZDA2VkszSkUrOWlReWl0aGpjZk5Pd25DYW9PN0k3cUFqOVFFZkpTCk1aUWMvVy80REhKZWJvMmtkMTF5b1hQVlRYWE91RXdMU0tDZWpCWEFCQlkwTVBOdVBVbWlYZVUwTzNUeWkzN0oKVFVLenJnY2Q3TnZsQTQxWTR4S2NPcUVBCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0='),
    InMemory::base64Encoded('LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEwNzhCUE96TFlFUkdDMHkrR2g0VQpLTjJjNklKc2NiekZMQ3B6ODhzVWJOV0sxemtqcWNEZEo2YkYycXdTaWxTRkREUzN4VGc2Zjc1MEo5bWFkT2pmCkZ4dWZWZ0Rpc0x3dURIOFN3MEpBUGlWNElNeDVaRzFhRXpmblZKSFdDQmFraXJnRHhzSWxrNkVTdGtzUklZbzkKNnhOaFRqZkkwR2J3OFdaSWovV3VMOFNUdHprejBNQ3EzblZ4WWptN0Z3LzNOMGJTeFlTbkxZd3NoemlLejlHMApCTEhudjV1eVRiUnVLOHVnVDdyRGVzRy9yeWFPWW5nV0QydDNOZldwRGF1cXY1MkZvYVpZWkpDVXJtanF5K2NWCnhCY3lPVTczTDUxMGVldkJsWE1TdkdDM3haSGNhYkZ4cmVhd0czb2RJZjFPWkNDeEFLci9EL1R4azJhWW5DbTYKNXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t')
);

$auth = new \Delight\Auth\Auth($db, $JWTconfig);

$auth->loginWithUsername('username', 'password');
$issuedToken = $auth->issueToken();
$issuedTokenString = $auth->generateJWTtoken();

d($auth);
d($issuedToken);
d($issuedTokenString);
echo("---<br>");
d($issuedToken->signature()->hash());
d($issuedToken->payload());
d($JWTconfig->signingKey());
d($JWTconfig->signer()->verify($issuedToken->signature()->hash(), $issuedToken->payload(), LocalFileReference::file(__DIR__ . '/public.key')));
d($auth->validateToken($issuedTokenString));
echo("---<br>");
d($auth->getUserId());
d($auth->isLoggedIn());
echo("logout");
$auth->logOut();
d($auth->getUserId());
d($auth->isLoggedIn());
echo("auth with token");
$auth->authenticateWithToken($issuedTokenString);
d($auth->getUserId());
d($auth->isLoggedIn());

function varName( $v ) {
    //bad function here, using it only for testing
    $trace = debug_backtrace();
    $vLine = file( __FILE__ );
    $fLine = $vLine[ $trace[1]['line'] - 1 ];
    preg_match( "#\\$(\w+)#", $fLine, $match );
    return $match[0];
}

function d($var) {
?>
<details>
    <summary><?php echo(varName($var)); ?></summary>
    <pre><?php var_dump($var); ?></pre>
</details>
<?php
}