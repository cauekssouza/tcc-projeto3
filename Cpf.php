<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function strlen;
use function ctype_digit;

final class Cpf extends Sanitization
{
    public function validateCpf(string $attribute, mixed $value): bool
    {
        // Sanitiza (por exemplo, removendo pontos, traços etc.)
        $c = $this->sanitize($value);

        // Garante que é string
        if (!is_string($c)) {
            return false;
        }

        // Remove espaços extras, se necessário
        $c = trim($c);

        // Deve ter exatamente 11 caracteres
        if (strlen($c) !== 11) {
            return false;
        }

        // Deve conter apenas dígitos
        if (!ctype_digit($c)) {
            return false;
        }

        // Rejeita CPFs com todos os dígitos iguais (ex: 00000000000, 11111111111)
        if ($c === str_repeat($c[0], 11)) {
            return false;
        }

        // Calcula primeiro dígito verificador
        $sum = 0;
        for ($i = 0, $weight = 10; $weight >= 2; $i++, $weight--) {
            $sum += (int) $c[$i] * $weight;
        }

        $remainder = $sum % 11;
        $digit1 = ($remainder < 2) ? 0 : 11 - $remainder;

        if ((int) $c[9] !== $digit1) {
            return false;
        }

        // Calcula segundo dígito verificador
        $sum = 0;
        for ($i = 0, $weight = 11; $weight >= 2; $i++, $weight--) {
            $sum += (int) $c[$i] * $weight;
        }

        $remainder = $sum % 11;
        $digit2 = ($remainder < 2) ? 0 : 11 - $remainder;

        if ((int) $c[10] !== $digit2) {
            return false;
        }

        return true;
    }
}
