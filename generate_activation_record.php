<?php

// Main script to generate the activation record.

// This script will:
// 1. Include necessary helper functions/classes.
// 2. Retrieve device information.
// 3. Generate various certificates and data blobs.
// 4. Assemble the plist.
// 5. Output the final HTML.

// Placeholder for future functions and logic.

/**
 * Retrieves device-specific information.
 *
 * In a real scenario, this function would execute the `ideviceinfo` command
 * and parse its output. For this script, it returns mock data.
 *
 * @return array Associative array of device information.
 */
function get_device_info(): array
{
    // Mock data based on the example plist
    return [
        'SerialNumber' => 'F4GTGYKJHG7F', // Example from deviceActivation_response.txt
        'ProductType' => 'iPhone9,3',    // Example from deviceActivation_response.txt
        'UniqueDeviceID' => '0a46305ca2ec80f97f28a22b7b977c45a01c828a', // Example from deviceActivation_response.txt
        'InternationalMobileEquipmentIdentity' => '355324087826421', // Example from deviceActivation_response.txt
        'ActivationRandomness' => '16447A85-BCE5-4DF8-8112-CCD5431D6352', // Example, new UUID
        'ActivityURL' => 'https://albert.apple.com/deviceservices/activity', // Example
        'PhoneNumberNotificationURL' => 'https://albert.apple.com/deviceservices/phoneHome', // Example
        // Add other necessary fields as identified
    ];
}

require_once 'certificate_utils.php';

// Example usage:
$deviceInfo = get_device_info();
// print_r($deviceInfo); // For testing

echo "PHP Activation Record Generator - Device Info Loaded (Mocked)\n";

/**
 * Generates the AccountTokenCertificate.
 *
 * @param array $deviceInfo Device information array.
 * @param string &$privateKeyOutput To store the generated private key for this cert.
 * @return string Base64 encoded certificate.
 */
function generate_account_token_certificate(array $deviceInfo, string &$privateKeyOutput): string
{
    $dn = [
        "countryName" => "US",
        "stateOrProvinceName" => "California",
        "localityName" => "Cupertino",
        "organizationName" => "Apple Inc.",
        "organizationalUnitName" => "Apple iPhone",
        "commonName" => "iPhone Activation Account Token CA", // Example CN
        "emailAddress" => "test@example.com"
    ];

    $validityDays = 365 * 5; // 5 years, example

    $certPem = generate_self_signed_cert($dn, $validityDays, $privateKeyOutput, $publicKeyOutput);

    if (!$certPem) {
        die("Failed to generate AccountTokenCertificate.\n");
    }

    // The certificate data in plist is just the base64 content without PEM headers/footers.
    $certData = preg_replace('/-+BEGIN CERTIFICATE-+\r?\n?/', '', $certPem);
    $certData = preg_replace('/-+END CERTIFICATE-+\r?\n?/', '', $certData);
    return base64_encode(base64_decode(trim($certData))); // Ensure it's a clean base64 string
}


// Generate AccountTokenCertificate
$accountTokenCertPrivateKey = '';
$accountTokenCertificateBase64 = generate_account_token_certificate($deviceInfo, $accountTokenCertPrivateKey);

echo "\nGenerated AccountTokenCertificate (Base64):\n";
echo $accountTokenCertificateBase64 . "\n";
// echo "\nAssociated Private Key (AccountTokenCertificate):\n";
// echo $accountTokenCertPrivateKey . "\n";


/**
 * Generates the DeviceCertificate.
 *
 * @param array $deviceInfo Device information array.
 * @param string &$privateKeyOutput To store the generated private key for this cert.
 * @return string Base64 encoded certificate.
 */
function generate_device_certificate(array $deviceInfo, string &$privateKeyOutput): string
{
    // Device certificates often have the UDID or Serial in the CN or as a SAN
    $commonName = $deviceInfo['UniqueDeviceID'] ?? 'AppleDevice'; // Use UDID if available

    $dn = [
        "countryName" => "US",
        "stateOrProvinceName" => "California",
        "localityName" => "Cupertino",
        "organizationName" => "Apple Inc.",
        "organizationalUnitName" => "Apple iPhone Production", // Slightly different OU
        "commonName" => $commonName,
        "emailAddress" => "devicecerts@example.com"
    ];

    $validityDays = 365 * 10; // Device certs might be longer lived

    $certPem = generate_self_signed_cert($dn, $validityDays, $privateKeyOutput, $publicKeyOutput);

    if (!$certPem) {
        die("Failed to generate DeviceCertificate.\n");
    }

    $certData = preg_replace('/-+BEGIN CERTIFICATE-+\r?\n?/', '', $certPem);
    $certData = preg_replace('/-+END CERTIFICATE-+\r?\n?/', '', $certData);
    return base64_encode(base64_decode(trim($certData)));
}

// Generate DeviceCertificate
$deviceCertPrivateKey = '';
$deviceCertificateBase64 = generate_device_certificate($deviceInfo, $deviceCertPrivateKey);

echo "\nGenerated DeviceCertificate (Base64):\n";
echo $deviceCertificateBase64 . "\n";


/**
 * Generates the UniqueDeviceCertificate, which appears to be a pair of concatenated certificates.
 *
 * @param array $deviceInfo Device information array.
 * @param string &$privateKey1Output To store the private key of the first cert.
 * @param string &$privateKey2Output To store the private key of the second cert.
 * @return string Base64 encoded concatenated certificates.
 */
function generate_unique_device_certificate_pair(array $deviceInfo, string &$privateKey1Output, string &$privateKey2Output): string
{
    // First certificate (e.g., device unique cert)
    $dn1 = [
        "countryName" => "US",
        "stateOrProvinceName" => "California",
        "localityName" => "Cupertino",
        "organizationName" => "Apple Inc.",
        "organizationalUnitName" => "Apple iPhone Hardware CA", // Example OU
        "commonName" => "Apple iPhone Unit " . ($deviceInfo['SerialNumber'] ?? 'UnknownSN'), // More specific CN
    ];
    $cert1Pem = generate_self_signed_cert($dn1, 365 * 5, $privateKey1Output, $publicKey1Output);
    if (!$cert1Pem) {
        die("Failed to generate first part of UniqueDeviceCertificate.\n");
    }

    // Second certificate (e.g., an intermediate or root CA that would sign the first)
    // For now, also self-signed for simplicity.
    $dn2 = [
        "countryName" => "US",
        "stateOrProvinceName" => "California",
        "localityName" => "Cupertino",
        "organizationName" => "Apple Inc.",
        "organizationalUnitName" => "Apple Root CA", // Example Root CA OU
        "commonName" => "Apple Root CA - G3 Replacement", // Example
    ];
    $cert2Pem = generate_self_signed_cert($dn2, 365 * 20, $privateKey2Output, $publicKey2Output); // Longer validity for a "CA"
    if (!$cert2Pem) {
        die("Failed to generate second part of UniqueDeviceCertificate.\n");
    }

    // The example data is a single base64 blob.
    // This implies the raw certificate data (not the PEM strings themselves with BEGIN/END)
    // might be concatenated, or the PEMs are concatenated then the whole thing base64'd.
    // The example data shows the BEGIN/END markers for both when decoded.
    // The odd string "ukMtH9RdSQvHzBx7FiBGr7/KcmlxX/XwoWeWnWb6IRM=" is present between the two certs in the decoded example.
    // This is unusual. It might be an artifact of how it was copied, or some non-standard concatenation.
    // For now, let's try concatenating the PEM strings.
    // The actual data in the plist is the base64 of the raw DER bytes of the certs, potentially concatenated.
    // The provided example has PEM markers *within* the base64 data, meaning the base64 is of the PEM string itself.

    // Let's re-examine the example:
    // Cert1_PEM_base64 + Base64(Maybe("ukMtH9RdSQvHzBx7FiBGr7/KcmlxX/XwoWeWnWb6IRM=")) + Cert2_PEM_base64
    // Or, more likely, the entire string including the BEGIN/END CERTIFICATE lines for both, plus that middle part,
    // is what's base64 encoded.
    // The string "ukMtH9RdSQvHzBx7FiBGr7/KcmlxX/XwoWeWnWb6IRM=" is 44 chars, which is a valid base64 block.
    // If decoded, it's 33 bytes. This is highly irregular for standard certificate concatenation.
    //
    // Given the example, it seems the base64 data itself for each cert (without BEGIN/END)
    // is NOT what's concatenated then re-encoded.
    // Instead, the full PEM strings are present in the decoded data.
    // The string "LS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLXVrTXRIOVJkU1F2SHpCeDdGaUJHcjcvS2NtbHhYL1h3b1dlV25XYjZJUk09Ci0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQo="
    // when decoded, is "-----END CERTIFICATE-----ukMtH9RdSQvHzBx7FiBGr7/KcmlxX/XwoWeWnWb6IRM=-----BEGIN CERTIFICATE-----"
    // This means "ukMtH9RdSQvHzBx7FiBGr7/KcmlxX/XwoWeWnWb6IRM=" is literally part of the string between the two certs.
    // This is extremely odd. For now, I will replicate this oddity.

    $pem1Data = preg_replace('/-+(BEGIN|END) CERTIFICATE-+\r?\n?/', '', $cert1Pem);
    $pem1Data = trim(str_replace(["\r", "\n"], '', $pem1Data));

    $pem2Data = preg_replace('/-+(BEGIN|END) CERTIFICATE-+\r?\n?/', '', $cert2Pem);
    $pem2Data = trim(str_replace(["\r", "\n"], '', $pem2Data));

    // Reconstruct PEMs for concatenation with the strange middle part
    $fullPemString = "-----BEGIN CERTIFICATE-----\n" . chunk_split($pem1Data, 64, "\n") . "-----END CERTIFICATE-----"
                   . "ukMtH9RdSQvHzBx7FiBGr7/KcmlxX/XwoWeWnWb6IRM=" // The odd string from the example
                   . "-----BEGIN CERTIFICATE-----\n" . chunk_split($pem2Data, 64, "\n") . "-----END CERTIFICATE-----\n";

    return base64_encode($fullPemString);
}


// Generate UniqueDeviceCertificate
$uniqueDeviceCert1PrivateKey = '';
$uniqueDeviceCert2PrivateKey = '';
$uniqueDeviceCertificateBase64 = generate_unique_device_certificate_pair($deviceInfo, $uniqueDeviceCert1PrivateKey, $uniqueDeviceCert2PrivateKey);

echo "\nGenerated UniqueDeviceCertificate (Base64):\n";
echo $uniqueDeviceCertificateBase64 . "\n";


/**
 * Returns the FairPlayKeyData.
 *
 * This data is highly proprietary and its generation is complex.
 * For this script, we use the static value from the example activation record.
 *
 * @return string Base64 encoded FairPlayKeyData.
 */
function get_fairplay_key_data(): string
{
    return 'LS0tLS1CRUdJTiBDT05UQUlORVItLS0tLQpBQUVBQVQzOGVycGgzbW9HSGlITlFTMU5YcTA1QjFzNUQ2UldvTHhRYWpKODVDWEZLUldvMUI2c29Pd1kzRHUyClJtdWtIemlLOFV5aFhGV1N1OCtXNVI4dEJtM3MrQ2theGpUN2hnQVJ5S0o0U253eE4vU3U2aW9ZeDE3dVFld0IKZ1pqc2hZeitkemlXU2I4U2tRQzdFZEZZM0Z2bWswQXE3ZlVnY3JhcTZqU1g4MUZWcXc1bjNpRlQwc0NRSXhibgpBQkVCQ1JZazlodFlML3RlZ0kzc29DeUZzcmM1TTg1OXhTcHRGNFh2ejU1UVZDQkw1OFdtSzZnVFNjVHlVSDN3CjJSVERXUjNGRnJxR2Y3aTVCV1lxRVdLMEkzNFgyTWJsZnR4OTM3bmI3SysrTFVkYk81YnFZaDM0bTREcUZwbCsKZkRnaDVtdU1DNkVlWWZPeTlpdEJsbE5ad2VlUWJBUmtKa2FHUGJ5aEdpYlNCcTZzR0NrQVJ2WTltT2ZNT3hZYgplWitlNnhBRmZ4MjFwUk9BM0xZc0FmMzBycmtRc0tKODVBRHZVMzFKdUFibnpmeGQzRnorbHBXRi9FeHU5QVNtCm1XcFFTY1VZaXF5TXZHUWQ5Rnl6ZEtNYk1SQ1ExSWpGZVhOUWhWQTY0VzY4M0czbldzRjR3a3lFRHl5RnI1N2QKcUJ3dFA4djRhSXh4ZHVSODVaT0lScWs0UGlnVlUvbVRpVUVQem16Wlh2MVB3ZzNlOGpjL3pZODZoYWZHaDZsZApMbHAyTU9uakNuN1pmKzFFN0RpcTNrS280bVo0MHY0cEJOV1BodnZGZ0R5WDdSLy9UaTBvbCtnbzc1QmR2b1NpCmljckUzYUdOc0hhb0d6cE90SHVOdW5HNTh3UW9BWXMwSUhQOGNvdmxPMDhHWHVRUlh1NVYyM1VyK2ZLQ2t5dm8KSEptYWVmL29ZbmR3QzAvK1pUL2FOeTZKUUEzUzg1Y3dzaFE3YXpYajlZazNndzkzcE0xN3I5dExGejNHWDRQegoyZWhMclVOTCtZcSs1bW1zeTF6c2RlcENGMldkR09KbThnajluMjdHUDNVVnhUOVA4TkI0K1YwNzlEWXd6TEdiCjhLdGZCRExSM2cwSXppYkZQNzZ5VC9FTDUwYmlacU41SlNLYnoxS2lZSGlGS05CYnJEbDlhWWFNdnFJNHhOblgKNVdpZk43WDk3UHE0TFQzYW5rcmhUZUVqeXFxeC9kYmovMGh6bG1RRCtMaW5UV29SU2ZFVWI2Ni9peHFFb3BrbQp3V2h6dXZPMUVPaTRseUJUV09MdmxUY1h1WUpwTUpRZHNCb0dkSVdrbm80Qnp5N3BESXMvSXpNUVEzaUpEYVc3CnBiTldrSUNTdytEVWJPdDVXZFZqN0FHTEFUR2FVRW1ZS1dZNnByclo2bks0S1lReFJDN3NvdDc2SHJaajJlVnoKRVl4cm1hVy9lRHhuYVhDOGxCNXpCS0wrQ1pDVmZhWHlEdmV1MGQvdzhpNGNnRTVqSkF6S2FFcmtDeUlaSm5KdApYTkJhOEl3M3Y3aW1GNlhPREFEaU9KK3hGTjdJQXlzem5YMEw4RFJ6Mkc1d2I5clllMW03eDRHM3duaklxZG1hCm9DdzZINnNPcFFRM2RWcVd0UDhrL1FJbk5ONnV2dVhEN3kvblVsdlVqcnlVbENlcFlzeDhkOFNScWw1M3d0SGwKYWxabUpvRWh0QTdRVDBUZHVVUmJ6M2dabWVXKzJRM3BlazVHaVBKRStkci83YklHRGxhdWZJVkVQTXc4clg3agpVNTVRWmZ6MHZyc3p5eGg3U0x1SDc3RmVGd3ljVlJId0t6NkFndlpOb0R2b0dMWk9KTi82V1NxVlhmczYxUEdPCmN0d29WVkkzejhYMGtWUXRHeUpjQTlFYjN0SFBHMzMrM1RpYnBsL2R0VW1LRU5WeUUrQTJUZDN5RFRydVBFQmsKZHJhM3pFc25ZWXFxR2I3aVhvMVB6Y3crUGo5QTRpQlE2cTl3RGtBbEFDdTZsZnUwCi0tLS0tRU5EIENPTlRBSU5FUi0tLS0tCg==';
}

// Get FairPlayKeyData
$fairPlayKeyDataBase64 = get_fairplay_key_data();
echo "\nUsing static FairPlayKeyData (Base64):\n";
echo $fairPlayKeyDataBase64 . "\n";

/**
 * Returns the static WildcardTicket.
 * Its generation is complex and proprietary.
 * @return string Base64 encoded WildcardTicket.
 */
function get_static_wildcard_ticket(): string
{
    return "MIICqgIBATALBgkqhkiG9w0BAQsvcJ8/DJNBAOkxALTzeBNbpp9ABGAAAACfSxRTueQpg/yza8WjD9qGr07bukTICZ+HbQc1UyQIeCZCn5c9DAAAAADu7u7u7u7u5+XPgQAAAAAn5c/BAEAAACfl0AEAAQAAAJ+XQQQBAAAAn5dMBAAAAAAEggEAC/WKb1cn3xEf5xMU8XfI9jbrU/oA+An+bQphyarg8gr6mNhgf6PZ12oEUIiWqscqwOoLSXVqc+dkonlaIZ2apETCc0OX9v03tpjyPIhfjh/C51VK/xJ5i0/2/Mm0p7tBQSevkb20J25AZRZOAES22g4oKLF/Ww9ZgmRb+uQ+8La779PEltgzQ7i9toSaoLzlpFMtvsLWVim+Zw+phRX+9I7X7uSTC1vsSxSQzZx6wZkXN+PDzXZ8u3a7HV98gk72LyFkDPU39zlO5F6zvhWOVqcfWn4XJnPPvIZ6VvzK/n4Y3dFIE3hlayPEzatElA3sF6aExMgA+z6sj2KKOCCASAwCwYJKoZIhvcNAQEBB4IBDwAwdgIKAQECskU9F2dz8TtWBq2D8AdsqcYU5H16DxZmCHEw6U9p3d8vaeCBdF5VFwETmXJBcTJo/SiPLezdAmG40RfAsxg4sIok0CPHsTp1mon0JBqaI68SdmN0L+AsEbmNK4AjjMX6GM5t7w5mdXpgZygRtGQDNv2P7HnZji6PS9r/D4Q50CJNaLrGJZ1UVBNcKkKNMDD2pxrFnxdSLTj51xVITBU71Tdl7KghSskP8WagOONk6Z0IcOCwIaWct9A/+Aso4yk5/PDh1YUhiUIO+z1TL5TdiHLITgc8NXHagB/yiOEEzOx2pcZVXjWfSZlKRHi66VlWVHgT+bEHZl0/sdAgMBAAE=";
}

/**
 * Generates the AccountToken JSON string and then base64 encodes it.
 *
 * @param array $deviceInfo Associative array of device information.
 * @return string Base64 encoded AccountToken.
 */
function generate_account_token(array $deviceInfo): string
{
    $accountTokenData = [
        "InternationalMobileEquipmentIdentity" => $deviceInfo['InternationalMobileEquipmentIdentity'] ?? '',
        "PhoneNumberNotificationURL" => $deviceInfo['PhoneNumberNotificationURL'] ?? 'https://albert.apple.com/deviceservices/phoneHome',
        "SerialNumber" => $deviceInfo['SerialNumber'] ?? '',
        "ProductType" => $deviceInfo['ProductType'] ?? '',
        "UniqueDeviceID" => $deviceInfo['UniqueDeviceID'] ?? '',
        "WildcardTicket" => get_static_wildcard_ticket(),
        "PostponementInfo" => new stdClass(), // Empty JSON object {}
        "ActivationRandomness" => $deviceInfo['ActivationRandomness'] ?? '',
        "ActivityURL" => $deviceInfo['ActivityURL'] ?? 'https://albert.apple.com/deviceservices/activity',
    ];

    // Ensure consistent key order like the example for better comparison, though not strictly necessary for JSON
    $orderedAccountTokenData = [
        "InternationalMobileEquipmentIdentity" => $accountTokenData["InternationalMobileEquipmentIdentity"],
        "PhoneNumberNotificationURL" => $accountTokenData["PhoneNumberNotificationURL"],
        "SerialNumber" => $accountTokenData["SerialNumber"],
        "ProductType" => $accountTokenData["ProductType"],
        "UniqueDeviceID" => $accountTokenData["UniqueDeviceID"],
        "WildcardTicket" => $accountTokenData["WildcardTicket"],
        "PostponementInfo" => $accountTokenData["PostponementInfo"],
        "ActivationRandomness" => $accountTokenData["ActivationRandomness"],
        "ActivityURL" => $accountTokenData["ActivityURL"],
    ];


    $jsonAccountToken = json_encode($orderedAccountTokenData, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    // The example output for AccountToken is compact, not pretty printed, and has specific formatting for the JSON string.
    // Let's try to match it more closely by removing pretty print and ensuring specific formatting if possible.
    // The example from plist:
    // ewoJIkludGVybmF0aW9uYWxNb2JpbGVFcXVpcG1lbnRJZGVudGl0eSIgPSAiMzU1MzI0MDg3ODI2NDIxIjsKCSJQaG9uZU51bWJlck5vdGlmaWNhdGlvblVSTCIgPSAiaHR0cHM6Ly9hbGJlcnQuYXBwbGUuY29tL2RldmljZXNlcnZpY2VzL3Bob25lSG9tZSI7CgkiU2VyaWFsTnVtYmVyIiA9ICJGNEdUR1lKWkhHN0YiOwoJIlByb2R1Y3RUeXBlIiA9ICJpUGhvbmU5LDMiOwoJIlVuaXF1ZURldmljZUlEIiA9ICIwYTQ2MzA1Y2EyZWM4MGY5N2YyOGEyMmI3Yjk3N2M0NWEwMWM4MjhhIjsKCSJXaWxkY2FyZFRpY2tldCIgPSAiTUlJQ3FnSUJBVEFMQmdrcWhraUc5dzBCQVFzeGNKOC9ESk5CQU9reEFMVHplQk5icHA5QUJHQUFBQUNmU3hSVHVlUXBnL3l6YThXakQ5cUdyMDdidWtUSUNaK0hiUWMxVXlRSWVDWkNuNWM5REFBQUFBRHU3dTd1N3U3dTc1K1hQZ1FBQUFBQW41Yy9CQUVBQUFDZmwwQUVBUUFBQUorWFFRUUJBQUFBbjVkTUJBQUFBQUFFZ2dFQUMvV0tiMWNuM3hFZjV4TVU4WGZJOWpiclUvb0ErQW4rYlFwaHlhcmc4Z3I2bU5oZ2Y2UFoxMm9FVUlpV3FzY3F3T29MU1hWcWMrZGtvbmxhSVoyYXBFVENjME9YOXYwM3Rwamd5UEloZmpoL0M1MVZLL3hKNWkwLzIvTW0wcDdUQjFRU2V2dWtiMjBKMjVBWlJaT0FFUzIyZzRvS0xGL1d3OVpnbVJicit1USs4TGE3NzlQRWx0Z3pRN2k5dG9TYW9MemxwRk10dnNMV1ZpbStadytwaFJYKzlJN1g3dVNUQzF2c1N4U1F6Wng2d1prWE4rUER6WFo4dTNhN0hWOThnazcyTHlGa0RQVTM5emxPNUY2enZoZU9WcWNmV240WEpuUFB2SVo2VnZ6SzIvbjRZM2RGSUUzaGxheVBFemF0RWxBM3NGNmFFeE1HZ0ErejZzajJLS09DQVNBd0N3WUpLb1pJaHZjTkFRRUJBNElCRHdBd2dnRUtBb0lCQVFDc2tVOUYyZHo4VHRXQnEyRDhBZHNxY1lTNTFINjZEeFptQ0hFdzZVOXAzZDh2amFFY0JkRjVWRndFVG1XSkJjVEpvL1NpUExlemRBbUc0MFJmQXN4ZzRzSW9rMENQaEtzVHAxbW9uMEpCcWFpNjhTZG1OMEwrQXNFYm1OSzRBampNWDZHTTV0N3c1bWRYcGdaeWlnUnRHUURuVjJQN0huT1pqNjlQUzlyL0Q0UTUwQ0pOYUxyR0paMVVWQk5jS2tKTlRNRDJweHJIbnhkU0xUajUxeFZJVEJVNzFUZGw3S2doU3NrUDhXYWdPT05rNkowSWNPQ3dJYVdjdDlBLytBc280eWs1L1BEaDFZVWhiVWlJTyt6MVRMNVRkaUhMSVRnYzhOWEhhZ0IveWlPRUV6T3gycGNaVlhYandmU1psS1JIajY2VmxXVkhnVCtiRUhabDAvc2RBZ01CQUFFPSI7CgkiUG9zdHBvbmVtZW50SW5mbyIgPSB7fTsKCSJBY3RpdmF0aW9uUmFuZG9tbmVzcyIgPSAiMTY0NDdBODUtQkNFNS00REY4LTgxMTItQ0NENTQzMUQ2MzUyIjsKCSJBY3Rpdml0eVVSTCIgPSAiaHR0cHM6Ly9hbGJlcnQuYXBwbGUuY29tL2RldmljZXNlcnZpY2VzL2FjdGl2aXR5IjsKfQ==
    // The decoded JSON has tabs and newlines, and " = " between key and value. This is not standard JSON.
    // This looks more like a string representation of a dictionary or plist snippet itself rather than pure JSON.
    // Given the context of a plist, it's possible this "AccountToken" is a string formatted to look like a text-based plist dict.
    // Let's try to replicate that format.

    $tokenString = "{\n";
    $tokenString .= "\t\"InternationalMobileEquipmentIdentity\" = \"" . $accountTokenData['InternationalMobileEquipmentIdentity'] . "\";\n";
    $tokenString .= "\t\"PhoneNumberNotificationURL\" = \"" . $accountTokenData['PhoneNumberNotificationURL'] . "\";\n";
    $tokenString .= "\t\"SerialNumber\" = \"" . $accountTokenData['SerialNumber'] . "\";\n";
    $tokenString .= "\t\"ProductType\" = \"" . $accountTokenData['ProductType'] . "\";\n";
    $tokenString .= "\t\"UniqueDeviceID\" = \"" . $accountTokenData['UniqueDeviceID'] . "\";\n";
    $tokenString .= "\t\"WildcardTicket\" = \"" . $accountTokenData['WildcardTicket'] . "\";\n";
    $tokenString .= "\t\"PostponementInfo\" = {};\n"; // Special case for empty dict
    $tokenString .= "\t\"ActivationRandomness\" = \"" . $accountTokenData['ActivationRandomness'] . "\";\n";
    $tokenString .= "\t\"ActivityURL\" = \"" . $accountTokenData['ActivityURL'] . "\";\n";
    $tokenString .= "}";

    return base64_encode($tokenString);
}

// Generate AccountToken
$accountTokenBase64 = generate_account_token($deviceInfo);
echo "\nGenerated AccountToken (Base64):\n";
echo $accountTokenBase64 . "\n";


/**
 * Generates the AccountTokenSignature.
 *
 * This function signs the raw AccountToken data (before its final base64 encoding for the plist)
 * using the private key associated with the AccountTokenCertificate.
 *
 * @param string $rawAccountToken The raw string data of the AccountToken (not base64 encoded).
 * @param string $privateKeyPem The PEM encoded private key for signing.
 * @return string Base64 encoded signature.
 */
function generate_account_token_signature(string $rawAccountToken, string $privateKeyPem): string
{
    $pkey = openssl_pkey_get_private($privateKeyPem);
    if (!$pkey) {
        die("Failed to get private key for AccountTokenSignature: " . openssl_error_string() . "\n");
    }

    $signature = '';
    // Determine the algorithm from the key type, default to SHA256
    $pkeyDetails = openssl_pkey_get_details($pkey);
    $algo = OPENSSL_ALGO_SHA256; // Default, common for RSA
    if (isset($pkeyDetails['type'])) {
        if ($pkeyDetails['type'] === OPENSSL_KEYTYPE_RSA) {
            // SHA256withRSA is common
        } elseif ($pkeyDetails['type'] === OPENSSL_KEYTYPE_EC) {
            // SHA256withECDSA might be appropriate
            // Note: openssl_sign with EC keys might require specific curve setup or be implicit
        }
        // Add more specific algorithm choices if needed based on key type or cert properties
    }


    if (!openssl_sign($rawAccountToken, $signature, $pkey, $algo)) {
        die("Failed to sign AccountToken: " . openssl_error_string() . "\n");
    }
    openssl_pkey_free($pkey);

    return base64_encode($signature);
}

// We need the raw AccountToken string for signing.
// The generate_account_token function currently returns a base64 encoded string.
// Let's modify it or get the raw string before encoding.

// For now, let's assume generate_account_token can give us the raw string
// or we re-construct it here based on its logic for clarity.
$tokenDataArray = [
    "InternationalMobileEquipmentIdentity" => $deviceInfo['InternationalMobileEquipmentIdentity'] ?? '',
    "PhoneNumberNotificationURL" => $deviceInfo['PhoneNumberNotificationURL'] ?? 'https://albert.apple.com/deviceservices/phoneHome',
    "SerialNumber" => $deviceInfo['SerialNumber'] ?? '',
    "ProductType" => $deviceInfo['ProductType'] ?? '',
    "UniqueDeviceID" => $deviceInfo['UniqueDeviceID'] ?? '',
    "WildcardTicket" => get_static_wildcard_ticket(),
    "PostponementInfo" => new stdClass(),
    "ActivationRandomness" => $deviceInfo['ActivationRandomness'] ?? '',
    "ActivityURL" => $deviceInfo['ActivityURL'] ?? 'https://albert.apple.com/deviceservices/activity',
];
$rawAccountTokenString = "{\n";
$rawAccountTokenString .= "\t\"InternationalMobileEquipmentIdentity\" = \"" . $tokenDataArray['InternationalMobileEquipmentIdentity'] . "\";\n";
$rawAccountTokenString .= "\t\"PhoneNumberNotificationURL\" = \"" . $tokenDataArray['PhoneNumberNotificationURL'] . "\";\n";
$rawAccountTokenString .= "\t\"SerialNumber\" = \"" . $tokenDataArray['SerialNumber'] . "\";\n";
$rawAccountTokenString .= "\t\"ProductType\" = \"" . $tokenDataArray['ProductType'] . "\";\n";
$rawAccountTokenString .= "\t\"UniqueDeviceID\" = \"" . $tokenDataArray['UniqueDeviceID'] . "\";\n";
$rawAccountTokenString .= "\t\"WildcardTicket\" = \"" . $tokenDataArray['WildcardTicket'] . "\";\n";
$rawAccountTokenString .= "\t\"PostponementInfo\" = {};\n";
$rawAccountTokenString .= "\t\"ActivationRandomness\" = \"" . $tokenDataArray['ActivationRandomness'] . "\";\n";
$rawAccountTokenString .= "\t\"ActivityURL\" = \"" . $tokenDataArray['ActivityURL'] . "\";\n";
$rawAccountTokenString .= "}";


$accountTokenSignatureBase64 = generate_account_token_signature($rawAccountTokenString, $accountTokenCertPrivateKey);
echo "\nGenerated AccountTokenSignature (Base64):\n";
echo $accountTokenSignatureBase64 . "\n";


/**
 * Returns the static base64 encoded RegulatoryInfo.
 * @return string
 */
function get_static_regulatory_info_base64(): string
{
    // Decoded: {"elabel":{"bis":{"regulatory":"R-41094897"}}}
    return "eyJlbGFiZWwiOnsiYmlzIjp7InJlZ3VsYXRvcnkiOiJSLTQxMDk0ODk3In19fQ==";
}


/**
 * Assembles the complete XML plist string.
 *
 * @param string $accountTokenCertificateB64
 * @param string $deviceCertificateB64
 * @param string $fairPlayKeyDataB64
 * @param string $accountTokenB64
 * @param string $accountTokenSignatureB64
 * @param string $uniqueDeviceCertificateB64
 * @param string $regulatoryInfoB64
 * @return string The XML plist as a string.
 */
function generate_activation_plist(
    string $accountTokenCertificateB64,
    string $deviceCertificateB64,
    string $fairPlayKeyDataB64,
    string $accountTokenB64,
    string $accountTokenSignatureB64,
    string $uniqueDeviceCertificateB64,
    string $regulatoryInfoB64
): string {
    // Helper to properly indent and format base64 data within <data> tags, similar to Apple's plists
    $format_data_tag_content = function(string $base64string): string {
        return "\n" . chunk_split($base64string, 76, "\n") . "\t\t"; // 76 is a common line length for PEM like data
    };

    $plist = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
    $plist .= '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' . "\n";
    $plist .= '<plist version="1.0">' . "\n";
    $plist .= '<dict>' . "\n";
    $plist .= "\t" . '<key>ActivationRecord</key>' . "\n";
    $plist .= "\t" . '<dict>' . "\n";

    $plist .= "\t\t" . '<key>unbrick</key><true/>' . "\n"; // Static value from example

    $plist .= "\t\t" . '<key>AccountTokenCertificate</key><data>' . $format_data_tag_content($accountTokenCertificateB64) . '</data>' . "\n";
    $plist .= "\t\t" . '<key>DeviceCertificate</key><data>' . $format_data_tag_content($deviceCertificateB64) . '</data>' . "\n";
    $plist .= "\t\t" . '<key>RegulatoryInfo</key><data>' . $format_data_tag_content($regulatoryInfoB64) . '</data>' . "\n";
    $plist .= "\t\t" . '<key>FairPlayKeyData</key><data>' . $format_data_tag_content($fairPlayKeyDataB64) . '</data>' . "\n";
    $plist .= "\t\t" . '<key>AccountToken</key><data>' . $format_data_tag_content($accountTokenB64) . '</data>' . "\n";
    $plist .= "\t\t" . '<key>AccountTokenSignature</key><data>' . $format_data_tag_content($accountTokenSignatureB64) . '</data>' . "\n";
    $plist .= "\t\t" . '<key>UniqueDeviceCertificate</key><data>' . $format_data_tag_content($uniqueDeviceCertificateB64) . '</data>' . "\n";

    $plist .= "\t" . '</dict>' . "\n";
    $plist .= '</dict>' . "\n";
    $plist .= '</plist>' . "\n";

    return $plist;
}

// Get static RegulatoryInfo
$regulatoryInfoBase64 = get_static_regulatory_info_base64();

// Assemble the plist
$activationPlistXml = generate_activation_plist(
    $accountTokenCertificateBase64,
    $deviceCertificateBase64,
    $fairPlayKeyDataBase64,
    $accountTokenBase64,
    $accountTokenSignatureBase64,
    $uniqueDeviceCertificateBase64,
    $regulatoryInfoBase64
);

echo "\nGenerated Activation Plist XML:\n";
// We might not want to echo the raw plist if the final output is HTML
// echo $activationPlistXml;


/**
 * Generates the final HTML output embedding the plist.
 *
 * @param string $plistXml The XML plist string.
 * @return string The complete HTML page as a string.
 */
function generate_final_html(string $plistXml): string
{
    // Escape the plist XML for safe embedding within JavaScript context if necessary,
    // but here it's directly embedded as text content of a script tag.
    // Standard HTML escaping for the content of the script tag is important if it could contain e.g. </script>
    // However, plists are XML and shouldn't contain that sequence directly in their character data.
    // The main concern is ensuring the XML itself is well-formed.

    $html = '<!DOCTYPE html>' . "\n";
    $html .= '<html>' . "\n";
    $html .= '   <head>' . "\n";
    $html .= '      <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />' . "\n";
    $html .= '      <meta name="keywords" content="iTunes Store" />' . "\n";
    $html .= '      <meta name="description" content="iTunes Store" />' . "\n";
    $html .= '      <title>iPhone Activation</title>' . "\n";
    // Links to Apple's static CSS - these might not be reachable or necessary for basic validation
    // but are included for completeness based on the example.
    $html .= '      <link href="https://static.deviceservices.apple.com/deviceservices/stylesheets/common-min.css" charset="utf-8" rel="stylesheet" />' . "\n";
    $html .= '      <link href="https://static.deviceservices.apple.com/deviceservices/stylesheets/styles.css" charset="utf-8" rel="stylesheet" />' . "\n";
    $html .= '      <link href="https://static.deviceservices.apple.com/deviceservices/stylesheets/IPAJingleEndPointErrorPage-min.css" charset="utf-8" rel="stylesheet" />' . "\n";
    $html .= '      <script id="protocol" type="text/x-apple-plist">' . htmlspecialchars($plistXml, ENT_XML1 | ENT_COMPAT, 'UTF-8') . '</script>' . "\n";
    $html .= '      <script>' . "\n";
    $html .= '         	var protocolElement = document.getElementById("protocol");' . "\n";
    $html .= '         	var protocolContent = protocolElement.innerText; // or .textContent for wider compatibility
    $html .= '         	// In a real iTunes environment, this iTunes object would exist.
    $html .= '         	if (typeof iTunes !== "undefined" && typeof iTunes.addProtocol === "function") {' . "\n";
    $html .= '         	    iTunes.addProtocol(protocolContent);' . "\n";
    $html .= '         	} else {' . "\n";
    $html .= '         	    console.log("iTunes object or iTunes.addProtocol not found. Protocol content logged below:");' . "\n";
    $html .= '         	    console.log(protocolContent);' . "\n";
    $html .= '         	}' . "\n";
    $html .= '      </script>' . "\n";
    $html .= '   </head>' . "\n";
    $html .= '   <body>' . "\n";
    $html .= '   </body>' . "\n";
    $html .= '</html>';

    return $html;
}

// Generate the final HTML output
$finalHtmlOutput = generate_final_html($activationPlistXml);

// Output the final HTML
// Clear any previous echos if this is the only desired output
// For command line usage, just printing it is fine.
// If it were a web script, you'd set Content-Type: text/html.
header('Content-Type: text/html; charset=utf-8');
echo $finalHtmlOutput;

?>
