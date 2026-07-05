<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function preg_match;
use function mb_strlen;
use function ctype_digit;

final class Cpf extends Sanitization
{
    public function validateCpf($attribute, $value): bool
    {
        // Sanitiza e força string
        $c = (string) $this->sanitize($value);

        // Verifica tamanho
        if (mb_strlen($c) !== 11) {
            return false;
        }

        // Verifica se contém apenas números
        if (!ctype_digit($c)) {
            return false;
        }

        // Rejeita CPFs com todos os dígitos iguais
        if (preg_match('/^(\d)\1{10}$/', $c)) {
            return false;
        }

        // Valida primeiro dígito verificador
        $sum = 0;
        for ($i = 0, $weight = 10; $weight >= 2; $i++, $weight--) {
            $sum += $c[$i] * $weight;
        }

        $digit1 = ($sum % 11 < 2) ? 0 : 11 - ($sum % 11);

        if ((int)$c[9] !== $digit1) {
            return false;
        }

        // Valida segundo dígito verificador
        $sum = 0;
        for ($i = 0, $weight = 11; $weight >= 2; $i++, $weight--) {
            $sum += $c[$i] * $weight;
        }

        $digit2 = ($sum % 11 < 2) ? 0 : 11 - ($sum % 11);

        if ((int)$c[10] !== $digit2) {
            return false;
        }

        return true;
    }
}
