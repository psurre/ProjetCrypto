import iaik.asn1.structures.AlgorithmID;
import iaik.x509.X509Certificate;

import java.security.*;
import java.security.cert.CertificateException;

/**
 * A utility class that provides a method for generating a signed
 * X.509 certificate from a given base certificate.  All fields of the
 * base certificate are preserved, except for the IssuerDN, the
 * public key, and the signature.
 */
public class CryptoX509 {

    public static X509Certificate
    generateCertificate(
            PublicKey subjectPublicKey,
            Principal issuerName,
            PrivateKey issuerPrivateKey,
            AlgorithmID algorithm,
            X509Certificate baseCert
    )
    {
        X509Certificate cert = null;

        try {
            cert = new X509Certificate(baseCert.getEncoded());
            cert.setPublicKey(subjectPublicKey);
            cert.setIssuerDN(issuerName);
            cert.sign(algorithm, issuerPrivateKey);
        } catch (InvalidKeyException e) {
            System.err.println("X509 Certificate Generation Error: Invalid Key");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("X509 Certificate Generation Error: No Such Algorithm");
            e.printStackTrace();
        } catch (CertificateException e) {
            System.err.println("X509 Certificate Generation Error: Certificate Exception");
            e.printStackTrace();
        }
        return cert;
    }
}