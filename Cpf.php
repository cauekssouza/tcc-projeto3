<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Security;

final class Auth
{
    private string $secretKey;

    public function __construct()
    {
        // A chave deve vir de variável de ambiente ou vault seguro
        $this->secretKey = getenv('APP_AUTH_SECRET') ?: '';
    }

    /**
     * Autentica um valor usando HMAC-SHA256 (OWASP recomendado)
     */
    public function auth(string $value, string $providedHash): bool
    {
        if ($this->secretKey === '') {
            throw new \RuntimeException('Chave secreta não configurada.');
        }

        // Gera hash seguro usando HMAC-SHA256
        $expectedHash = hash_hmac('sha256', $value, $this->secretKey);

        // Comparação resistente a timing attacks
        return hash_equals($expectedHash, $providedHash);
    }
}
