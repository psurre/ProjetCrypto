import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Utility methods for creating a new signed certificate.
 *
 * @author Srinivas Inguva
 * @author Liz Stinson
 * @author Priyank Patel
 */

public class CryptoSignCert {
    private static KeyStore load(String ksFile, String ksPass) {
        KeyStore tmp = null;
        try {
            tmp = KeyStore.getInstance("jks");
            tmp.load(new FileInputStream(ksFile),ksPass.toCharArray());
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return null;
        } catch (KeyStoreException kse) {
            System.err.println("Error while parsing keystore");
            kse.printStackTrace();
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return tmp;
    }

    /**
     * Forge certificate which is identical to the given base certificate, except is signed
     * by the "CA" certificate in caKS, and has the associated IssuerDN.
     *
     * The new cert will be signed by a the CA whose public/private keys are contained
     * in the caKS KeyStore (under the alias caAlias).
     *
     */

    public static X509Certificate forgeCert(KeyStore caKS, char[] caKSPass, String caAlias,
                                            String commonName, X509Certificate baseCert)
            throws Exception
    {
        //java.security.Security.addProvider(new iaik.security.provider.IAIK());
        java.security.Security.addProvider(new BouncyCastleProvider());

        //CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");

        PrivateKey pk = (PrivateKey) caKS.getKey(caAlias,caKSPass);
        if (pk == null) {
            System.out.println(TLSHackConstants.PKERROR);
        } else {
            if (CryptoProxyServer.debugFlag)
                System.out.println(TLSHackConstants.PKFORMAT+pk.getFormat());
        }
        X509Certificate rootCert = (X509Certificate) caKS.getCertificate(caAlias);
        /*
        Certificate tmp = caKS.getCertificate(caAlias);
        X509Certificate caCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(tmp.getEncoded()));

        Principal issuer = caCert.getSubjectDN();
        // Type d'algorithme utilisé
        AlgorithmIdentifier alg = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP);
        //AlgorithmID alg = AlgorithmID.sha256WithRSAEncryption;
        PublicKey subjectPubKey = caCert.getPublicKey();

        X509Certificate x509 = CryptoX509.generateCertificate(subjectPubKey,issuer,pk,alg,baseCert);*/
        X509Certificate x509 = CryptoX509.generateBCCertificate(commonName, rootCert);
        if (CryptoProxyServer.debugFlag) {
            System.out.println(TLSHackConstants.NEWCERT);
            System.out.println(x509.toString());
        }

        return x509;
    }

    /* Self test */
    public static void main(String[] args) throws Exception {
        String caKeystore = args[0];
        String caKSPass = args[1];
        String caAlias = args[2];
        String commonName = args[3];

        KeyStore caKS = load(caKeystore,caKSPass);
        PrivateKey pk = (PrivateKey) caKS.getKey(caAlias,caKSPass.toCharArray());

        X509Certificate newCert = forgeCert(caKS, caKSPass.toCharArray(), caAlias, commonName, null);

        KeyStore newKS = KeyStore.getInstance("jks");
        newKS.load(null, null);

        newKS.setKeyEntry("myKey", pk, caKSPass.toCharArray(), new Certificate[] {newCert});
        newKS.store(new FileOutputStream("newkeystore"),caKSPass.toCharArray());
    }

}