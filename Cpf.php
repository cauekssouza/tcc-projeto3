<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function preg_match;
use function strlen;
use function ctype_digit;

final class Cpf extends Sanitization
{
    public function validateCpf(string $attribute, mixed $value): bool
    {
        // Garante string e remove tudo que não for dígito
        $c = $this->sanitize((string) $value);

        // Só aceita exatamente 11 dígitos
        if (!ctype_digit($c) || strlen($c) !== 11) {
            return false;
        }

        // Rejeita CPFs com todos os dígitos iguais (ex: 11111111111)
        if (preg_match('/^(\d)\1{10}$/', $c) === 1) {
            return false;
        }

        // Calcula primeiro dígito verificador
        $sum = 0;
        for ($weight = 10, $i = 0; $weight >= 2; $weight--, $i++) {
            $sum += (int) $c[$i] * $weight;
        }

        $remainder = $sum % 11;
        $digit1 = ($remainder < 2) ? 0 : 11 - $remainder;

        if ((int) $c[9] !== $digit1) {
            return false;
        }

        // Calcula segundo dígito verificador
        $sum = 0;
        for ($weight = 11, $i = 0; $weight >= 2; $weight--, $i++) {
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
