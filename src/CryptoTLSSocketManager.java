import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Création de sockets TLS.
 *
 */
public final class CryptoTLSSocketManager implements CryptoSocketManager
{
    final ServerSocketFactory m_serverSocketFactory;
    final SocketFactory m_clientSocketFactory;
    final SSLContext m_sslContext;

    public KeyStore ks = null;

    /**
     * Création d'un ServerSocketFactory
     * initilisé avec le certificat de la root CA
     */
    public CryptoTLSSocketManager()
            throws IOException, GeneralSecurityException
    {
        m_sslContext = SSLContext.getInstance(TLSHackConstants.TLSSTANDARD);

        // Un seul algorithme PKIX
        final KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        final String keyStoreFile = System.getProperty(TLSHackConstants.KEYSTORELIB, TLSHackConstants.ROOTCAFILE);
        char[] keyStorePassword = System.getProperty(TLSHackConstants.KEYSTOREPASSLIB, TLSHackConstants.ROOTCAKSPASS).toCharArray();
        final String keyStoreType = System.getProperty(TLSHackConstants.KEYSTORETYPELIB, TLSHackConstants.ROOTCAKSTYPE);
        //KeyStore Decode
        byte[] passTmp = java.util.Base64.getDecoder().decode(String.valueOf(keyStorePassword));
        keyStorePassword = new String (passTmp).toCharArray();

        final KeyStore keyStore;

        if (keyStoreFile != null) {
            keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

            this.ks = keyStore;
        } else {
            keyStore = null;
        }

        keyManagerFactory.init(keyStore, keyStorePassword);

        m_sslContext.init(keyManagerFactory.getKeyManagers(),
                new TrustManager[] { new TrustEveryone() },
                null);

        m_clientSocketFactory = m_sslContext.getSocketFactory();
        m_serverSocketFactory = m_sslContext.getServerSocketFactory();
    }

    /**
     * Création d'un ServerSocketFactory
     * initialisé avec le certificate généré dynamique signé par la root CA
     */
    public CryptoTLSSocketManager(String remoteCN, X509Certificate remoteServerCert)
            throws Exception
    {
        m_sslContext = SSLContext.getInstance(TLSHackConstants.TLSSTANDARD);

        final KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());

        final String keyStoreFile =
                System.getProperty(TLSHackConstants.KEYSTORELIB, TLSHackConstants.ROOTCAFILE);
        char[] keyStorePassword =
                System.getProperty(TLSHackConstants.KEYSTOREPASSLIB, TLSHackConstants.ROOTCAKSPASS).toCharArray();
        byte[] passTmp = java.util.Base64.getDecoder().decode(String.valueOf(keyStorePassword));
        keyStorePassword = new String (passTmp).toCharArray();

        final String keyStoreType =
                System.getProperty(TLSHackConstants.KEYSTORETYPELIB, TLSHackConstants.ROOTCAKSTYPE);

        final KeyStore keyStore;

        assert keyStoreFile != null;

        keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

        //Récupération de la clé privée stockée dans le certificat de la rootCA
        PrivateKey pk = (PrivateKey) keyStore.getKey(TLSHackConstants.ROOTALIAS,keyStorePassword);
        // Appel à la fonction pour forger les certificats
        X509Certificate newCert = CryptoSignCert.forgeCert(keyStore, keyStorePassword,TLSHackConstants.ROOTALIAS,
                remoteCN);

        KeyStore newKS = KeyStore.getInstance(keyStoreType);
        newKS.load(null, null);
        newKS.setKeyEntry(TLSHackConstants.CERTALIAS, pk, keyStorePassword, new Certificate[] {newCert});
        keyManagerFactory.init(newKS, keyStorePassword);
        m_sslContext.init(keyManagerFactory.getKeyManagers(),
                new TrustManager[] { new TrustEveryone() },
                null);

        m_clientSocketFactory = m_sslContext.getSocketFactory();
        m_serverSocketFactory = m_sslContext.getServerSocketFactory();
    }

    public final ServerSocket createServerSocket(String localHost,
                                                 int localPort,
                                                 int timeout)
            throws IOException
    {
        final SSLServerSocket socket =
                (SSLServerSocket)m_serverSocketFactory.createServerSocket(
                        localPort, 50, InetAddress.getByName(localHost));

        socket.setSoTimeout(timeout);

        socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

        return socket;
    }

    public final Socket createClientSocket(String remoteHost, int remotePort)
            throws IOException
    {
        final SSLSocket socket =
                (SSLSocket)m_clientSocketFactory.createSocket(remoteHost,
                        remotePort);

        socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

        socket.startHandshake();

        return socket;
    }

    /**
     * Partie qui est peut-être problématique.
     * On réalise une interception TLS, donc on ne vérifie pas forcément la chaine de certification.
     * A investiguer avec plus de temps !
     */
    private static class TrustEveryone implements X509TrustManager
    {
        public void checkClientTrusted(X509Certificate[] chain,
                                       String authenticationType) {
        }

        public void checkServerTrusted(X509Certificate[] chain,
                                       String authenticationType) {
        }

        public X509Certificate[] getAcceptedIssuers()
        {
            return null;
        }
    }
}

