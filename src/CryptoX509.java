import iaik.asn1.structures.AlgorithmID;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.test.FixedSecureRandom;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * A utility class that provides a method for generating a signed
 * X.509 certificate from a given base certificate.  All fields of the
 * base certificate are preserved, except for the IssuerDN, the
 * public key, and the signature.
 */
public class CryptoX509 {

    public static X509Certificate
    generateRootCA(

    )throws Exception{
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(TLSHackConstants.KEY_ALGORITHM, TLSHackConstants.BC_PROVIDER);
        keyPairGenerator.initialize(TLSHackConstants.KEY_SIZE);

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name(TLSHackConstants.ROOTCACN);
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(TLSHackConstants.SIGNATURE_ALGORITHM).setProvider(TLSHackConstants.BC_PROVIDER).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(TLSHackConstants.BC_PROVIDER).getCertificate(rootCertHolder);

        writeCertToFileBase64Encoded(rootCert, TLSHackConstants.ROOTCACERT);
        exportKeyPairToKeystoreFile(rootKeyPair, rootCert, TLSHackConstants.DEFAULT_ALIAS, TLSHackConstants.ROOTCAFILE, TLSHackConstants.ROOTCAKSTYPE, TLSHackConstants.ROOTCAKSPASS);
        return rootCert;
    }
    public static X509Certificate
    generateBCCertificate(
            String commonName,
            X509Certificate rootCert
    ) throws Exception {
        X509Certificate cert = null;
        X500Name rootCertIssuer = new X500Name(TLSHackConstants.ROOTCACN);
        // Calcul du temps de validité du certificat
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();
        X500Name issuedCertSubject = new X500Name("CN="+commonName);
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        try {
            // Initialisation d'un générateur de clés
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(TLSHackConstants.KEY_ALGORITHM, TLSHackConstants.BC_PROVIDER);
            keyPairGenerator.initialize(TLSHackConstants.KEY_SIZE);
            // Génération d'un couple de clés pour le certificat à émettre
            KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();
            // Intialisation des constructeurs de p10 et du CSR (Certificate Signing Request)
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
            JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(TLSHackConstants.SIGNATURE_ALGORITHM).setProvider(TLSHackConstants.BC_PROVIDER);
            // Signer la nouvelle paire de clefs avec la clef privée de notre CA racine.
            PrivateKey rootPrivKey = getROOTCAPKey(TLSHackConstants.ROOTCAKSTYPE, TLSHackConstants.DEFAULT_ALIAS, TLSHackConstants.ROOTCAFILE, TLSHackConstants.ROOTCAKSPASS);
            ContentSigner csrContentSigner = csrBuilder.build(rootPrivKey);
            PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

            // Use the Signed KeyPair and CSR to generate an issued Certificate
            // Here serial number is randomly generated. In general, CAs use
            // a sequence to generate Serial number and avoid collisions
            X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());
            JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

            // Add Extensions
            // Use BasicConstraints to say that this Cert is not a CA
            issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            // Add Issuer cert identifier as Extension
            issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
            issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

            // Add intended key usage extension if needed
            //issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));
            issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            // Add DNS name is cert is to used for SSL
            issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
                    new GeneralName(GeneralName.dNSName, commonName),
                    //new GeneralName(GeneralName.iPAddress, "127.0.0.1")
            }));

            X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
            cert  = new JcaX509CertificateConverter().setProvider(TLSHackConstants.BC_PROVIDER).getCertificate(issuedCertHolder);
            // Verify the issued cert signature against the root (issuer) cert
            cert.verify(rootCert.getPublicKey(), TLSHackConstants.BC_PROVIDER);

            // Ecriture du nouveau certificat dans un fichier .cer
            writeCertToFileBase64Encoded(cert, commonName+".cer");
            // Export du nouveau certificat et de sa clef privée dans un keyStore qui lui est propre
            exportKeyPairToKeystoreFile(issuedCertKeyPair, cert, TLSHackConstants.DEFAULT_ALIAS, commonName+".pfx", TLSHackConstants.ROOTCAKSTYPE, TLSHackConstants.ROOTCAKSPASS);

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

    private static PrivateKey getROOTCAPKey(String storeType, String alias, String fileName, String storePass) throws Exception{
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
}