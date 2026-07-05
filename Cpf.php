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
        // Nunca use md5, sha1 ou hashes simples.
        // OWASP recomenda HMAC com SHA‑256 ou superior.
        $computedHash = hash_hmac(
            'sha256',
            $username . ':' . $password,
            $this->secretKey
        );

        // Exemplo: buscar hash armazenado no banco
        $storedHash = $this->getStoredHashForUser($username);

        // Comparação segura contra timing attacks
        return hash_equals($storedHash, $computedHash);
    }

    private function getStoredHashForUser(string $username): string
    {
        // Aqui você buscaria o hash real no banco.
        // Exemplo fictício:
        return 'hash_salvo_no_banco';
    }
}
