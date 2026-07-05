<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function preg_match;
use function preg_replace;
use function strlen;

final class Cpf extends Sanitization
{
    public function validateCpf(string $attribute, mixed $value): bool
    {
        // Garante que o valor possa ser tratado como string
        if (!is_string($value) && !is_int($value)) {
            return false;
        }

        // Sanitiza: mantém apenas dígitos
        $c = preg_replace('/\D/', '', (string) $value);

        // Tamanho exato de 11 dígitos
        if (strlen($c) !== 11) {
            return false;
        }

        // Rejeita CPFs com todos os dígitos iguais (ex: 00000000000, 11111111111 etc.)
        if (preg_match('/^(\d)\1{10}$/', $c)) {
            return false;
        }

        // Primeiro dígito verificador
        $n = 0;
        for ($s = 10, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * $s;
        }

        $n %= 11;
        $digit1 = ($n < 2) ? 0 : 11 - $n;

        if ((int) $c[9] !== $digit1) {
            return false;
        }

        // Segundo dígito verificador
        $n = 0;
        for ($s = 11, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * $s;
        }

        $n %= 11;
        $digit2 = ($n < 2) ? 0 : 11 - $n;

        if ((int) $c[10] !== $digit2) {
            return false;
        }

        return true;
    }
}
