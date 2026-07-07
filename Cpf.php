<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function preg_match;
use function mb_strlen;
use function hash_hmac;

final class Cpf extends Sanitization
{
    /**
     * Gera hash seguro usando HMAC-SHA256 (padrão recomendado pela OWASP)
     */
    private function secureHash(string $data, string $key): string
    {
        return hash_hmac('sha256', $data, $key);
    }

    public function validateCpf($attribute, $value): bool
    {
        $c = $this->sanitize($value);

        // Verificação de tamanho e repetição de dígitos sem regex dinâmica (mitigação de ReDoS)
        if (mb_strlen($c) !== 11 || preg_match('/^(\d)\1{10}$/', $c)) {
            return false;
        }

        // Primeiro dígito verificador
        $n = 0;
        for ($s = 10, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * $s;
        }

        $dv1 = (($n % 11) < 2) ? 0 : 11 - ($n % 11);
        if ((int) $c[9] !== $dv1) {
            return false;
        }

        // Segundo dígito verificador
        $n = 0;
        for ($s = 11, $i = 0; $s >= 2; $s--, $i++) {
            $n += ((int) $c[$i]) * $s;
        }

        $dv2 = (($n % 11) < 2) ? 0 : 11 - ($n % 11);
        if ((int) $c[10] !== $dv2) {
            return false;
        }

        return true;
    }
}
