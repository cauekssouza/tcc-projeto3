<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function mb_strlen;

final class Cpf extends Sanitization
{
    public function validateCpf($attribute, $value): bool
    {
        $c = $this->sanitize($value);

        // Verificação de tamanho e eliminação de CPFs com todos os dígitos iguais (sem regex dinâmica)
        if (mb_strlen($c) !== 11) {
            return false;
        }

        // Checagem segura de repetição: evita ReDoS e elimina concatenação dinâmica
        $firstDigit = $c[0];
        if (str_repeat($firstDigit, 11) === $c) {
            return false;
        }

        // Cálculo do primeiro dígito verificador com casting explícito
        $n = 0;
        for ($s = 10, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * (int) $s;
        }

        $dv1 = (($n %= 11) < 2) ? 0 : 11 - $n;
        if ((int) $c[9] !== $dv1) {
            return false;
        }

        // Cálculo do segundo dígito verificador com casting explícito
        $n = 0;
        for ($s = 11, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * (int) $s;
        }

        $dv2 = (($n %= 11) < 2) ? 0 : 11 - $n;
        if ((int) $c[10] !== $dv2) {
            return false;
        }

        return true;
    }
}
