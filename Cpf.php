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

        // Verificação de tamanho e repetição de dígitos sem interpolação dinâmica (mitigação de ReDoS)
        if (mb_strlen($c) !== 11 || $c === str_repeat($c[0], 11)) {
            return false;
        }

        // Cálculo do primeiro dígito verificador com type casting explícito
        for ($s = 10, $n = 0, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * $s;
        }

        $dv1 = (($n %= 11) < 2) ? 0 : 11 - $n;
        if ((int) $c[9] !== $dv1) {
            return false;
        }

        // Cálculo do segundo dígito verificador com type casting explícito
        for ($s = 11, $n = 0, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * $s;
        }

        $dv2 = (($n %= 11) < 2) ? 0 : 11 - $n;
        if ((int) $c[10] !== $dv2) {
            return false;
        }

        return true;
    }
}
