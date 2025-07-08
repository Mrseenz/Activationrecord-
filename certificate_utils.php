<?php

// Certificate Generation Utilities

/**
 * Generates a self-signed X.509 certificate.
 *
 * @param array $dn Distinguished Names for the certificate subject.
 * @param int $days Validity period in days.
 * @param string &$privateKeyOutput Reference to store the generated private key.
 * @param string &$publicKeyOutput Reference to store the generated public key.
 * @return string|false The generated certificate in PEM format, or false on failure.
 */
function generate_self_signed_cert(array $dn, int $days, string &$privateKeyOutput, string &$publicKeyOutput)
{
    $config = [
        "digest_alg" => "sha256",
        "private_key_bits" => 2048,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ];

    // Create private and public key
    $privKey = openssl_pkey_new($config);
    if (!$privKey) {
        // error_log("Failed to generate private key: " . openssl_error_string());
        return false;
    }

    // Generate a certificate signing request (CSR)
    $csr = openssl_csr_new($dn, $privKey, $config);
    if (!$csr) {
        // error_log("Failed to generate CSR: " . openssl_error_string());
        openssl_pkey_free($privKey);
        return false;
    }

    // Sign the CSR to create a self-signed certificate
    $x509 = openssl_csr_sign($csr, null, $privKey, $days, $config);
    if (!$x509) {
        // error_log("Failed to sign CSR: " . openssl_error_string());
        openssl_pkey_free($privKey);
        return false;
    }

    // Export the certificate
    if (!openssl_x509_export($x509, $certPem)) {
        // error_log("Failed to export certificate: " . openssl_error_string());
        openssl_pkey_free($privKey);
        openssl_x509_free($x509);
        return false;
    }

    // Export the private key
    if (!openssl_pkey_export($privKey, $privateKeyPem)) {
        // error_log("Failed to export private key: " . openssl_error_string());
        openssl_pkey_free($privKey);
        openssl_x509_free($x509);
        return false;
    }
    $privateKeyOutput = $privateKeyPem;

    // Export the public key
    $publicKeyDetails = openssl_pkey_get_details($privKey);
    if (!$publicKeyDetails || !isset($publicKeyDetails['key'])) {
        // error_log("Failed to get public key details: " . openssl_error_string());
        openssl_pkey_free($privKey);
        openssl_x509_free($x509);
        return false;
    }
    $publicKeyOutput = $publicKeyDetails['key'];

    openssl_pkey_free($privKey);
    openssl_x509_free($x509);

    return $certPem;
}

/**
 * Decodes a base64 encoded certificate.
 *
 * @param string $base64Cert The base64 encoded certificate string.
 * @return string The PEM formatted certificate.
 */
function decode_cert_from_base64(string $base64Cert): string
{
    $decoded = base64_decode($base64Cert);
    // Add PEM headers/footers if they are not present (common in plist data)
    if (strpos($decoded, '-----BEGIN CERTIFICATE-----') === false) {
        $decoded = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode(base64_decode($base64Cert)), 64, "\n") . "-----END CERTIFICATE-----\n";
    }
    return $decoded;
}

?>
