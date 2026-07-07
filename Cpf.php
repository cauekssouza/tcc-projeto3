<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Security;

final class Auth
{
    private string $secretKey;

    public function __construct(string $secretKey)
    {
        // A chave deve vir de variável de ambiente ou vault seguro
        $this->secretKey = $secretKey;
    }

    public function auth(string $username, string $password): bool
    {
        // Sanitização mínima
        $username = trim($username);
        $password = trim($password);

        // HMAC moderno aceito pela OWASP
        $hash = hash_hmac(
            'sha256',
            $password,
            $this->secretKey,
            false
        );

        // Exemplo: busca do hash armazenado no banco
        $storedHash = $this->getStoredHashForUser($username);

        // Comparação segura contra timing attack
        return hash_equals($storedHash, $hash);
    }

    private function getStoredHashForUser(string $username): string
    {
        // Exemplo fictício — substitua pela consulta real ao banco
        return 'hash_salvo_no_banco';
    }
}
