import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Classe qui propose une fonction de création de la root CA et une fonction de génération de certificats dynamiques
 *
 * @author Team Crypto M1
 * @version 0.9
 */
public class CryptoX509 {

    /**
     * Fonction de création du certificat de la root CA
     */
    public static void
    generateRootCA(

    )throws Exception{
        // Le provider de sécurité retenu est BouncyCastle
        Security.addProvider(new BouncyCastleProvider());

        // Initialisation du générateur de clefs
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(TLSHackConstants.KEY_ALGORITHM, TLSHackConstants.BC_PROVIDER);
        keyPairGenerator.initialize(TLSHackConstants.KEY_SIZE);

        // Initialisation des dates pour avoir une durée de validité d'1 an
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // Création de la paire de clefs pour le certificat root CA
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Le Subject et l'Issuer sont les même, c'est une root CA
        X500Name rootCertIssuer = new X500Name(TLSHackConstants.ROOTCACN);
        //Initialisation des constructeurs pour la signature de la CA
        //Paramètres : L'algorithme utilisé pour la signature, le provider et la clef privée root CA
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(TLSHackConstants.SIGNATURE_ALGORITHM).setProvider(TLSHackConstants.BC_PROVIDER).build(rootKeyPair.getPrivate());
        //Paramètres : le certificat de l'issuer (le même), le numéro de série du certificat, la date de début, la date de fin, le subject (le même) et la clef publique root CA
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertIssuer, rootKeyPair.getPublic());

        // ************************
        // Extensions au certificat
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        // Le certificat est une CA
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // SubjectKeyIdentifier : OBLIGATOIRE pour une CA -> Dérivée de la clef publique root CA
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, true, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));
        // keyUsage : OBLIGATOIRE pour une CA -> keyCertSign et cRLSign
        rootCertBuilder.addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.keyCertSign| X509KeyUsage.cRLSign));

        // ************************
        // Création du certificat X.509 et signature de celui-ci avec la clef privée root CA
        // Paramètre : Le signataire de contenu mentionné plus haut
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        // Création d'un objet certificat X509
        // Paramètre : Le détenteur de certificat mentionné plus haut
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(TLSHackConstants.BC_PROVIDER).getCertificate(rootCertHolder);

        // ************************
        // Ecriture du certificat généré dans un fichier .pem
        writeCertToPEM(rootCert, TLSHackConstants.ROOTCACERTPEM);
        // Export du certificat et de la clef privée dans un Key Store dédié
        exportKeyPairToKeystoreFile(rootKeyPair, rootCert, TLSHackConstants.ROOTALIAS, TLSHackConstants.ROOTCAFILE);
    }

    /**
     * Fonction de génération dynamique de certificats
     * @param commonName Nom du site pour lequel on veut créer un certificat
     * @param rootCert Certificat de la root CA
     * @return un certificat de type <code>X509Certificate</code>
     */
    public static X509Certificate
    generateBCCertificate(
            String commonName,
            X509Certificate rootCert
    ) throws Exception {

        X509Certificate cert = null;
        // On stocke le CN de la root CA dans un objet X500Name
        // On stocke le CN du site web dans un objet X500Name
        X500Name rootCertIssuer = new X500Name(TLSHackConstants.ROOTCACN);
        X500Name issuedCertSubject = new X500Name("CN="+commonName);

        // Génération du numéro de série du certificat dynamique
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Initialisation des dates pour avoir une durée de validité d'1 an
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        try {
            // Initialisation d'un générateur de clés
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(TLSHackConstants.KEY_ALGORITHM, TLSHackConstants.BC_PROVIDER);
            keyPairGenerator.initialize(TLSHackConstants.KEY_SIZE);

            // Génération d'un couple de clés pour le certificat à émettre
            KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

            // Initialisation du constructeur pour la requête de signature (P10)
            // Paramètres : le subject du site web, la clef publique du certificat
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
            // Initialisation du constructeur pour l'envoi de la requête de signature (CSR)
            // Paramètres : l'algorithme de signature et le provider
            JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(TLSHackConstants.SIGNATURE_ALGORITHM).setProvider(TLSHackConstants.BC_PROVIDER);

            // ********************************
            // Récupération de la clef privée de la root CA
            PrivateKey rootPrivKey = getROOTCAPKey();
            // Création du signataire de contenu avec la clef privée de la root CA
            // Paramètre : la clef privée de la root CA
            ContentSigner csrContentSigner = csrBuilder.build(rootPrivKey);
            // Création de la requête de signature
            // Paramètre : le signataire de contenu
            PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

            // Constructeur du certificat
            // Paramètres : le certificat de la root CA, le numéro de série, la date de début de validité, la date de fin de validité, le subject et le la clé publique génére pour le certificat
            X509v3CertificateBuilder issuedCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, issuedCertSubject, issuedCertKeyPair.getPublic());
            JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

            // ****************************
            // Add Extensions
            // Use BasicConstraints to say that this Cert is not a CA
            issuedCertBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

            // authorityKeyIdentifier => clef publique de l'autorité ayant signé le certificat, pour nous c'est la root CA.
            issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
            // subjectKeyIdentifier => clef publique du subject du certificat à créer.
            issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(issuedCertKeyPair.getPublic()));

            // Ajout du KeyUsage => Signature digitale
            issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature| KeyUsage.keyEncipherment));

            // Récupération et ajout d'autres noms DNS
            issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
                    new GeneralName(GeneralName.dNSName, commonName),
            }));

            // ***************************
            // Création et signature du certificat avec la clef privée de la root CA
            X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
            // ***************************
            // Conversion du certificat au format X.509
            cert  = new JcaX509CertificateConverter().setProvider(TLSHackConstants.BC_PROVIDER).getCertificate(issuedCertHolder);

            // Vérification de la signature du certificat avec la clef publique de la root CA
            boolean isValid = csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(rootCert.getPublicKey()));
            if (isValid) {
                // Ecriture du nouveau certificat dans un fichier .pem
                writeCertToPEM(cert, commonName+".pem");
                // Export du nouveau certificat et de sa clef privée dans un keyStore qui lui est propre
                exportKeyPairToKeystoreFile(issuedCertKeyPair, cert, TLSHackConstants.CERTALIAS, commonName + ".pfx");
                System.out.println(TLSHackConstants.CERTSUCCESS);
            }
        } catch (NoSuchAlgorithmException e) {
            System.err.println(TLSHackConstants.KEYGENERR);
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.err.println(TLSHackConstants.PROVIDERERR);
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            System.err.println(TLSHackConstants.OPEXCEPT);
            e.printStackTrace();
        } catch (CertificateException e) {
            System.err.println(TLSHackConstants.CERTERREXCEPT);
            e.printStackTrace();
        }
        return cert;
    }

    /**
     * Foncion pour exporter les clefs générées vers un Keystore
     * @param keyPair Paire de clefs à sauvegarder
     * @param certificate Certificat à sauvegarder
     * @param alias Alias utilisé pour se retrouver dans les enregistrements de la Keystore
     * @param fileName Nom du fichier Keystore
     */
    private static void exportKeyPairToKeystoreFile(KeyPair keyPair, X509Certificate certificate, String alias, String fileName) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(TLSHackConstants.ROOTCAKSTYPE, TLSHackConstants.BC_PROVIDER);
        sslKeyStore.load(null, null);
        // Récupération du mot de passe
        byte[] passTmp = java.util.Base64.getDecoder().decode(TLSHackConstants.ROOTCAKSPASS);
        String pass = new String (passTmp);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(), pass.toCharArray(),new X509Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, pass.toCharArray());
    }

    /**
     * Fonction pour récupérer la clef privée de la root CA (depuis le fichier Keystore)
     * @return Une clef privée
     */
    private static PrivateKey getROOTCAPKey() throws Exception{
        String storeType = TLSHackConstants.ROOTCAKSTYPE;
        String alias = TLSHackConstants.ROOTALIAS;
        String fileName = TLSHackConstants.ROOTCAFILE;
        String storePass = TLSHackConstants.ROOTCAKSPASS;
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, TLSHackConstants.BC_PROVIDER);
        FileInputStream fileKS = new FileInputStream(fileName);
        byte[] passTmp = java.util.Base64.getDecoder().decode(storePass);
        String pass = new String (passTmp);
        sslKeyStore.load(fileKS, pass.toCharArray());
        return (PrivateKey)sslKeyStore.getKey(alias, pass.toCharArray());
    }

    /**
     * Fonction pour écrire un certificat dans un fichier en utilisant un encodage en Base64.
     * Gardée pour un éventuel usage extérieur
     * @param certificate Le certificat X509 à persister
     * @param fileName Nom du fichier en sortie
     */
    private static void writeCertToFileBase64Encoded(X509Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }

    /**
     * Fonction pour écrire un certificat X509 dans un fichier au format .pem
     * @param certificate Le certificat X509 à persister
     * @param fileName Nom du fichier en sortie
     */
    private static void writeCertToPEM (X509Certificate certificate, String fileName) throws Exception{
        try (BufferedWriter writer = Files.newBufferedWriter(Path.of(fileName), UTF_8);
        PemWriter pemWriter = new PemWriter(writer)){
            pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
        }
    }
}