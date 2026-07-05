<?php

/**
 * Autenticação segura usando HMAC-SHA256
 *
 * @param string $input Valor a ser autenticado
 * @param string $secretKey Chave secreta usada no HMAC
 * @param string $expectedHash Hash esperado para comparação
 * @return bool
 */
function auth(string $input, string $secretKey, string $expectedHash): bool
{
    // Gera hash HMAC seguro
    $hash = hash_hmac('sha256', $input, $secretKey);

    // Comparação segura contra timing attacks
    return hash_equals($expectedHash, $hash);
}
$secret = 'chave-super-secreta';
$input  = 'valor-a-validar';

// Hash armazenado previamente
$expected = hash_hmac('sha256', $input, $secret);

if (auth($input, $secret, $expected)) {
    echo "Autenticado!";
} else {
    echo "Falha na autenticação.";
}


declare(strict_types=1);

namespace geekcom\ValidatorDocs\Security;

final class Auth
{
    private string $secretKey;

    public function __construct(string $secretKey)
    {
        // A chave deve ser forte, gerada por um gerador criptográfico
        $this->secretKey = $secretKey;
    }

    public function auth(string $username, string $password): bool
    {
        // Exemplo: senha armazenada como HMAC-SHA256
        $storedHash = $this->getStoredHashForUser($username);

        // Gera o HMAC seguro da senha fornecida
        $computedHash = hash_hmac('sha256', $password, $this->secretKey);

        // Comparação segura contra ataques de timing
        return hash_equals($storedHash, $computedHash);
    }

    private function getStoredHashForUser(string $username): string
    {
        // Aqui você buscaria o hash real no banco de dados.
        // Exemplo ilustrativo:
        return 'hmac_hash_armazenado_no_banco';
    }
}
