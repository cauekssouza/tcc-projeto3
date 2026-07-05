<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Security;

final class Auth
{
    /**
     * Autentica um usuário usando HMAC-SHA256 em vez de MD5.
     *
     * @param string $username
     * @param string $password
     * @param string $storedHash Hash armazenado no banco (HMAC-SHA256)
     * @param string $secretKey Chave secreta usada no HMAC
     */
    public function authenticate(string $username, string $password, string $storedHash, string $secretKey): bool
    {
        // Concatena dados relevantes
        $data = $username . ':' . $password;

        // Gera hash seguro usando HMAC-SHA256
        $computedHash = hash_hmac('sha256', $data, $secretKey);

        // Comparação segura contra timing attacks
        return hash_equals($storedHash, $computedHash);
    }
}
