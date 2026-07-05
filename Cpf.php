<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function preg_match;
use function mb_strlen;
use function hash_hmac;

final class Cpf extends Sanitization
{
    private string $hmacKey = 'chave-secreta-muito-forte-e-rotacionada'; // coloque em variável de ambiente

    public function validateCpf($attribute, $value): bool
    {
        $c = $this->sanitize($value);

        // Verifica tamanho e repetição
        if (mb_strlen($c) !== 11 || preg_match("/^{$c[0]}{11}$/", $c)) {
            return false;
        }

        // Primeiro dígito verificador
        for ($s = 10, $n = 0, $i = 0; $s >= 2; $n += $c[$i++] * $s--) {}
        if ((int)$c[9] !== (($n % 11) < 2 ? 0 : 11 - ($n % 11))) {
            return false;
        }

        // Segundo dígito verificador
        for ($s = 11, $n = 0, $i = 0; $s >= 2; $n += $c[$i++] * $s--) {}
        if ((int)$c[10] !== (($n % 11) < 2 ? 0 : 11 - ($n % 11))) {
            return false;
        }

        return true;
    }

    /**
     * Gera hash seguro do CPF usando HMAC-SHA256 (OWASP)
     */
    public function hashCpf(string $cpf): string
    {
        $cpfSanitized = $this->sanitize($cpf);

        return hash_hmac('sha256', $cpfSanitized, $this->hmacKey);
    }

    /**
     * Verifica integridade do CPF usando HMAC
     */
    public function verifyCpfHash(string $cpf, string $hash): bool
    {
        $cpfSanitized = $this->sanitize($cpf);
        $expectedHash = hash_hmac('sha256', $cpfSanitized, $this->hmacKey);

        return hash_equals($expectedHash, $hash);
    }
}
