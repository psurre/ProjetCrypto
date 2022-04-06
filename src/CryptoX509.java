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
 * A utility class that provides a method for generating a signed
 * X.509 certificate from a given base certificate.  All fields of the
 * base certificate are preserved, except for the IssuerDN, the
 * public key, and the signature.
 */
public class CryptoX509 {

    // Fonctionne de création du certificat de la root CA
    public static X509Certificate
    generateRootCA(

    )throws Exception{
        // Add the BouncyCastle Provider
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

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name(TLSHackConstants.ROOTCACN);
        X500Name rootCertSubject = rootCertIssuer;
        //Initialisation des constructeurs pour la signature de la CA
        //Paramètres : L'algorithme utilisé pour la signature, le provider et la clef privée root CA
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(TLSHackConstants.SIGNATURE_ALGORITHM).setProvider(TLSHackConstants.BC_PROVIDER).build(rootKeyPair.getPrivate());
        //Paramètres : le certificat de l'issuer (le même), le numéro de série du certificat, la date de début, la date de fin, le subject (le même) et la clef publique root CA
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

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
        exportKeyPairToKeystoreFile(rootKeyPair, rootCert, TLSHackConstants.DEFAULT_ALIAS, TLSHackConstants.ROOTCAFILE, TLSHackConstants.ROOTCAKSTYPE, TLSHackConstants.ROOTCAKSPASS);

        // ************************
        // On retourne le certificat de la root CA
        return rootCert;
    }

    // Fonction de création de certificat dynamique
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
            /* TODO à nettoyer : ContentSigner csrContentSigner = csrBuilder.build(issuedCertKeyPair.getPrivate());*/
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

            // Add intended key usage extension if needed
            //issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));
            issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

            // Add DNS name is cert is to used for SSL
            issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
                    new GeneralName(GeneralName.dNSName, commonName),
                    //new GeneralName(GeneralName.iPAddress, "127.0.0.1")
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
                //writeCertToFileBase64Encoded(cert, commonName + ".cer");
                // Export du nouveau certificat et de sa clef privée dans un keyStore qui lui est propre
                exportKeyPairToKeystoreFile(issuedCertKeyPair, cert, TLSHackConstants.DEFAULT_ALIAS, commonName + ".pfx", TLSHackConstants.ROOTCAKSTYPE, TLSHackConstants.ROOTCAKSPASS);
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

    private static void exportKeyPairToKeystoreFile(KeyPair keyPair, X509Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, TLSHackConstants.BC_PROVIDER);
        sslKeyStore.load(null, null);
        // Récupération du mot de passe
        byte[] passTmp = java.util.Base64.getDecoder().decode(storePass);
        String pass = new String (passTmp);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(), pass.toCharArray(),new X509Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, pass.toCharArray());
    }

    private static PrivateKey getROOTCAPKey() throws Exception{
        String storeType = TLSHackConstants.ROOTCAKSTYPE;
        String alias = TLSHackConstants.DEFAULT_ALIAS;
        String fileName = TLSHackConstants.ROOTCAFILE;
        String storePass = TLSHackConstants.ROOTCAKSPASS;
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, TLSHackConstants.BC_PROVIDER);
        FileInputStream fileKS = new FileInputStream(fileName);
        byte[] passTmp = java.util.Base64.getDecoder().decode(storePass);
        String pass = new String (passTmp);
        sslKeyStore.load(fileKS, pass.toCharArray());
        PrivateKey rootCAKey = (PrivateKey)sslKeyStore.getKey(alias, pass.toCharArray());
        return rootCAKey;
    }

    private static void writeCertToFileBase64Encoded(X509Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }

    private static void writeCertToPEM (X509Certificate certificate, String fileName) throws Exception{
        try (BufferedWriter writer = Files.newBufferedWriter(Path.of(fileName), UTF_8);
        PemWriter pemWriter = new PemWriter(writer)){
            pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
        }
    }
}