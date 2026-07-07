<?php

declare(strict_types=1);

namespace geekcom\ValidatorDocs\Rules;

use function preg_match;
use function mb_strlen;
use function hash_hmac;
use function hash_equals;

final class Cpf extends Sanitization
{
    private string $hmacKey = 'CHAVE-SECRETA-SEGURA-AQUI'; // idealmente vinda de env

    public function validateCpf($attribute, $value): bool
    {
        // Se o valor vier no formato: "cpf|assinatura"
        // Exemplo: "12345678909|a1b2c3..."
        [$rawCpf, $signature] = $this->extractSignedValue($value);

        // Verifica integridade usando HMAC-SHA256
        if (!$this->verifyHmac($rawCpf, $signature)) {
            return false;
        }

        $c = $this->sanitize($rawCpf);

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

    private function extractSignedValue(string $value): array
    {
        $parts = explode('|', $value, 2);
        return [
            $parts[0] ?? '',
            $parts[1] ?? ''
        ];
    }

    private function verifyHmac(string $cpf, string $signature): bool
    {
        if ($signature === '') {
            return false;
        }

        $expected = hash_hmac('sha256', $cpf, $this->hmacKey);
        return hash_equals($expected, $signature);
    }
}
