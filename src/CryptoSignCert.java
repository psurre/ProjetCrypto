import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * Classe permettant de demander la création et la signature des certificats générés dynamiquement.
 *
 * @author Team Crypto M1
 * @version 0.9
 */

public class CryptoSignCert {
    /**
     * Fonction pour charger les informations d'un KeyStore
     * @param ksFile Fichier KeyStore à charger
     * @param ksPass Mot de passe pour accéder au fichier KeyStore
     * @return Un objet de type <code>KeyStore</code>
     */
    private static KeyStore load(String ksFile, String ksPass) {
        KeyStore tmp = null;
        try {
            tmp = KeyStore.getInstance(TLSHackConstants.ROOTCAKSTYPE);
            tmp.load(new FileInputStream(ksFile),ksPass.toCharArray());
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return null;
        } catch (KeyStoreException kse) {
            System.err.println(TLSHackConstants.KSOPENERR+ksFile);
            kse.printStackTrace();
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return tmp;
    }

    /**
     * Fonction permettant de créer un certificat signé par notre root CA, l'Issuer etant aussi notre root CA.
     * @param caKS Keystore de la root CA utilisée pour signer le certificat
     * @param caKSPass Mot de passe pour accéder au Keystore de la root CA
     * @param caAlias Alias permettant de récupérer les clefs de la root CA
     * @param commonName Nom du serveur distant pour lequel on génère un nouveau certificat
     * @return Un certificat de type <code>X509Certificate</code>
     * @throws Exception
     */
    public static X509Certificate forgeCert(KeyStore caKS, char[] caKSPass, String caAlias,
                                            String commonName)
            throws Exception
    {
        // Le provider de sécurité retenu est BouncyCastle
        java.security.Security.addProvider(new BouncyCastleProvider());
        // Récupération de la clé  privée de la root CA
        // La clef est passée en clair dans la variable caKSPass
        PrivateKey pk = (PrivateKey) caKS.getKey(caAlias,caKSPass);

        if (pk == null) {
            System.out.println(TLSHackConstants.PKERROR);
        } else {
            if (CryptoProxyServer.debugFlag)
                System.out.println(TLSHackConstants.PKFORMAT+pk.getFormat());
        }
        // Récupération du certificat de la root CA
        X509Certificate rootCert = (X509Certificate) caKS.getCertificate(caAlias);

        // Appel à la fonction de génération du certificat
        // Classe CryptoX509
        X509Certificate x509 = CryptoX509.generateBCCertificate(commonName, rootCert);
        if (CryptoProxyServer.debugFlag) {
            System.out.println(TLSHackConstants.NEWCERT);
            System.out.println(x509.toString());
        }

        return x509;
    }
}