<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function preg_match;
use function mb_strlen;

final class Cpf extends Sanitization
{
    public function validateCpf($attribute, $value): bool
    {
        $c = $this->sanitize($value);

        // Verifica tamanho e elimina CPFs com todos os dígitos iguais (sem interpolação dinâmica)
        if (mb_strlen($c) !== 11 || preg_match('/^(\d)\1{10}$/', $c)) {
            return false;
        }

        // Cálculo do primeiro dígito verificador com casting explícito
        for ($s = 10, $n = 0, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * (int) $s;
        }

        $dv1 = (($n % 11) < 2) ? 0 : 11 - ($n % 11);
        if ((int) $c[9] !== $dv1) {
            return false;
        }

        // Cálculo do segundo dígito verificador com casting explícito
        for ($s = 11, $n = 0, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * (int) $s;
        }

        $dv2 = (($n % 11) < 2) ? 0 : 11 - ($n % 11);
        if ((int) $c[10] !== $dv2) {
            return false;
        }

        return true;
    }
}
