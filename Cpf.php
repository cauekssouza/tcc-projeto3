<?php

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
