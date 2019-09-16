package com.quest.keycloak.integration;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.keycloak.common.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.fail;

public class TestCryptoUtil {

    /** Parse a PEM certificate into the a X509 Certificate object */
    public static X509Certificate parseCertificate(String certB64){
        try {
            byte encodedCert[] = Base64.decode(certB64);
            ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(inputStream);
        }
        catch (IOException | CertificateException ex) {
            fail("Error while parsing certificate");
        }
        return null;
    }

    /** Parse a PKCS#1 formatted private key into a private key object */
    public static PrivateKey parsePrivateKey(String base64) throws IOException {
        RSAPrivateKey rsa   = RSAPrivateKey.getInstance(java.util.Base64.getDecoder().decode(base64));
        RSAPrivateCrtKeyParameters privateKeyParameter = new RSAPrivateCrtKeyParameters(
                rsa.getModulus(),
                rsa.getPublicExponent(),
                rsa.getPrivateExponent(),
                rsa.getPrime1(),
                rsa.getPrime2(),
                rsa.getExponent1(),
                rsa.getExponent2(),
                rsa.getCoefficient()
        );
        return new JcaPEMKeyConverter()
                .getPrivateKey(
                        PrivateKeyInfoFactory.createPrivateKeyInfo(
                                privateKeyParameter
                        )
                );
    }

}
