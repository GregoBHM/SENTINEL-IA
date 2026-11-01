/* Only harmless pipeline fixtures. These do not detect real malware families. */
rule OneGuard_Synthetic_Test
{
    meta:
        description = "Marcador sintético para verificar el pipeline; no es malware."
        threat_type = "Prueba sintética"
        confidence = 100
        risk_score = 0
        test_only = true
    strings:
        $marker = "ONEGUARD_SYNTHETIC_TEST_SIGNATURE" ascii
    condition:
        $marker
}

rule EICAR_Pipeline_Test
{
    meta:
        description = "Referencia textual EICAR para comprobar la detección de prueba."
        threat_type = "Prueba antivirus EICAR"
        confidence = 100
        risk_score = 0
        test_only = true
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar
}
