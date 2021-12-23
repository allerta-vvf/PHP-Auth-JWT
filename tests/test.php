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
    // You may use any HMAC variations (256, 384, and 512)
    new Signer\Rsa\Sha256(),
    // replace the value below with a key of your own!
    LocalFileReference::file(__DIR__ . '/private.key'),
    LocalFileReference::file(__DIR__ . '/public.key')
    // You may also override the JOSE encoder/decoder if needed by providing extra arguments here
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