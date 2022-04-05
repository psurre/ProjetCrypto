import javax.net.ssl.SSLSocket;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.asn1.x500.X500Name;

/**
 *
 * Un client proxy HTTPS envoie d'abord un message CONNECT au port du proxy.
 * Le proxy accepte la connexion et répond avec un 200 OK,
 * qui est la file d'attente du client pour envoyer des données TLS au proxy
 * Le proxy se contente de les transmettre au serveur identifié par le message CONNECT
 * du message CONNECT.
 *
 * L'API Java présente un défi particulier : elle permet aux sockets
 * d'être soit SSL soit non SSL, mais ne leur permet pas de changer leur
 * type en cours de route.Pour contourner ce problème, nous acceptons le CONNECT puis aveuglément
 * le reste du flux à travers une classe spéciale ProxyEngine (ProxySSLEngine) qui est instanciée pour
 * TLS.
 *
 * @author Team Crypto
 */
public class CryptoHTTPSWork extends CryptoWork
{
    // Déclaration des variables communes à la classe
    private String m_tempRemoteHost;
    private int m_tempRemotePort;
    private final Pattern m_httpsConnectPattern;
    private final ProxyTLSEngine m_proxyTLSEngine;
    private final HashMap<String, CryptoTLSSocketManager> cnMap = new HashMap<String, CryptoTLSSocketManager>();

    /** Constructeur de la classe
     * CryptoHTTPSocketManager => Classe pour créer un socket HTTP
     * CryptoTLSSocketManager => Classe pour créer un socket TLS
     * Crypofilter => Classe permettant de transférer les données d'une connexion TCP
     *
     */
    public CryptoHTTPSWork(CryptoHTTPSocketManager plainSocketFactory,
                            CryptoTLSSocketManager sslSocketFactory,
                            CryptoFilter requestFilter,
                            CryptoFilter responseFilter,
                            String localHost,
                            int localPort,
                            int timeout)
            throws IOException, PatternSyntaxException
    {
        // Nous configurons ce moteur pour gérer le HTTP simple et le déléguons
        // à un proxy TLS pour HTTPS.
        // Appel au constructeur de la classe mère : CryptoWork
        super(plainSocketFactory,
                requestFilter,
                responseFilter,
                new CryptoConnDet(localHost, localPort, "", -1, false),
                timeout);
        // Pattern pour intercepter le message CONNECT
        m_httpsConnectPattern =
                Pattern.compile("^CONNECT[ \\t]+([^:]+):(\\d+).*\r\n\r\n",
                        Pattern.DOTALL);

        // Dans le cas du HTTPS, nous utilisons notre socket ordinaire pour
        // accepter les connexions. Nous aspirons le peu que nous comprenons
        // depuis la requête entrante et on transmet le reste à travers notre moteur de proxy.
        // Le moteur de proxy écoute les tentatives de connexion (qui
        // viennent de nous), puis met en place une paire de threads qui poussent les données
        // dans les deux sens jusqu'à ce que le serveur ferme la connexion,
        // ou que nous le fassions (en réponse à notre client qui ferme la
        //  connexion). Le moteur gère les connexions multiples en
        //  en créant plusieurs paires de threads.

        assert sslSocketFactory != null;
        m_proxyTLSEngine = new ProxyTLSEngine(sslSocketFactory, requestFilter, responseFilter);

    }
    // Fonction de lancement du serveur proxy
    public void run()
    {
        final byte[] buffer = new byte[40960];

        while (true) {
            try {
                //Socket avec le message en clair
                final Socket localSocket = getServerSocket().accept();

                // Doit être un message de type CONNECT
                final BufferedInputStream in =
                        new BufferedInputStream(localSocket.getInputStream(),
                                buffer.length);

                in.mark(buffer.length);

                // Lecture du flux dans la variable buffer
                final int bytesRead = in.read(buffer);

                final String line =
                        bytesRead > 0 ?
                                new String(buffer, 0, bytesRead, TLSHackConstants.CRYPTOCHARSET) : "";

                // Recherche du CONNECT
                final Matcher httpsConnectMatcher =
                        m_httpsConnectPattern.matcher(line);
                if (httpsConnectMatcher.find()) {
                    // On a bien un CONNECT
                    // Suppression des autres messages en clair du client
                    while (in.read(buffer, 0, in.available()) > 0) {
                    }
                    // Champ 1 => Le serveur distant
                    final String remoteHost = httpsConnectMatcher.group(1);
                    // Champ 2 => Le port
                    final int remotePort = Integer.parseInt(httpsConnectMatcher.group(2));

                    // Serveur distant et port
                    final String target = remoteHost + ":" + remotePort;

                    if (CryptoProxyServer.debugFlag)
                        System.out.println(TLSHackConstants.NEWPROXCONN + target);

                    m_tempRemoteHost = remoteHost;
                    m_tempRemotePort = remotePort;

                    X509Certificate java_cert = null;
                    SSLSocket remoteSocket = null;
                    try {
                        // Création d'un socket pour récupérer le certificat du serveur distant
                        remoteSocket = (SSLSocket)
                                m_proxyTLSEngine.getSocketFactory().createClientSocket(remoteHost, remotePort);
                        //Récupération du "common name" du certificat :
                        java_cert = (X509Certificate) remoteSocket.getSession().getPeerCertificates()[0];
                    } catch (IOException ioe) {
                        ioe.printStackTrace();
                        sendClientResponse(localSocket.getOutputStream(),TLSHackConstants.TOCLIENTERR,remoteHost,remotePort);
                        // On fait un tour de boucle suivant sans traiter la suite
                        continue;
                    }
                    // Récupération du SubjectCN avec bouncycastle
                    X500Name x500name = new JcaX509CertificateHolder(java_cert).getSubject();
                    RDN cn = x500name.getRDNs(BCStyle.CN)[0];
                    String cName = cn.getFirst().getValue().toString();
                    System.out.println("Server SubjectDN : "+cName);

                    if (CryptoProxyServer.debugFlag)
                        System.out.println(TLSHackConstants.REMOTESRVCN+cName);

                    //We've already opened the socket, so might as well keep using it:
                    m_proxyTLSEngine.setRemoteSocket(remoteSocket);

                    //This is a CRUCIAL step:  we dynamically generate a new cert, based
                    // on the remote server's CN, and return a reference to the internal
                    // server socket that will make use of it.
                    ServerSocket localProxy = m_proxyTLSEngine.createServerSocket(cName,java_cert);

                    //Kick off a new thread to send/recv data to/from the remote server.
                    // Remote server's response data is made available via an internal
                    // SSLServerSocket.  All this work is handled by the m_proxySSLEngine:
                    new Thread(m_proxyTLSEngine, "HTTPS proxy TLS engine").start();

                    try {Thread.sleep(10);} catch (Exception ignore) {}

                    // Create a new socket connection to our proxy engine.
                    final Socket sslProxySocket =
                            getSocketFactory().createClientSocket(
                                    getConnectionDetails().getLocalHost(),
                                    localProxy.getLocalPort());

                    // Now set up a couple of threads to punt
                    // everything we receive over localSocket to
                    // sslProxySocket, and vice versa.
                    new Thread(new CryptoStreamCopy(
                            in, sslProxySocket.getOutputStream()),
                            "Copy to proxy engine for " + target).start();

                    final OutputStream out = localSocket.getOutputStream();

                    new Thread(new CryptoStreamCopy(
                            sslProxySocket.getInputStream(), out),
                            "Copy from proxy engine for " + target).start();

                    // Send a 200 response to send to client. Client
                    // will now start sending SSL data to localSocket.
                    sendClientResponse(out,"200 OK",remoteHost,remotePort);
                }
                else { //Not a CONNECT request.. nothing we can do.
                    System.err.println(
                            TLSHackConstants.PROXFAILEDTO);
                    System.err.println(line);
                    sendClientResponse(localSocket.getOutputStream(),TLSHackConstants.MSG501,TLSHackConstants.LOCALHOST,
                            getConnectionDetails().getLocalPort());
                }
            }
            catch (InterruptedIOException e) {
                System.err.println(TLSHackConstants.ACCEPTTIMEOUTMSG);
                break;
            }
            catch (Exception e) {
                e.printStackTrace(System.err);
            }
        }
    }

    private void sendClientResponse(OutputStream out, String msg, String remoteHost, int remotePort) throws IOException {
        final StringBuffer response = new StringBuffer();
        response.append("HTTP/1.0 ").append(msg).append("\r\n");
        response.append("Host: " + remoteHost + ":" +
                remotePort + "\r\n");
        response.append("Proxy-agent: CS255-MITMProxy/1.0\r\n");
        response.append("\r\n");
        out.write(response.toString().getBytes());
        out.flush();
    }

    /*
     * Utilisé pour canaliser les données entre un client (par exemple un navigateur web) et un
     * serveur TLS distant, auquel le client adresse une requête.
     *
     */
    private class ProxyTLSEngine extends CryptoWork {
        Socket remoteSocket = null;
        int timeout = 0;
        /*
         * Port number = 0 => system-allocated dynamic port number.
         */
        // Constructeur de la classe
        ProxyTLSEngine(CryptoTLSSocketManager socketFactory,
                       CryptoFilter requestFilter,
                       CryptoFilter responseFilter)
                throws IOException
        {
            super(socketFactory, requestFilter, responseFilter,
                    new CryptoConnDet(CryptoHTTPSWork.this.
                            getConnectionDetails().getLocalHost(),
                            0, "", -1, true),
                    0);
        }

        public final void setRemoteSocket(Socket s) {
            this.remoteSocket = s;
        }

        public final ServerSocket createServerSocket(String remoteServerCN, X509Certificate remoteServerCert)
                throws Exception
        {

            assert remoteServerCN != null;

            CryptoTLSSocketManager ssf = null;

            if (cnMap.get(remoteServerCN) == null) {
                //Instanciation d'un socketTLS avec un certificat basé sur le nom commun du serveur distant.
                System.out.println(TLSHackConstants.HTTPSCERTCREATE+remoteServerCN);
                ssf = new CryptoTLSSocketManager(remoteServerCN, remoteServerCert);
                cnMap.put(remoteServerCN, ssf);
            } else {
                if (CryptoProxyServer.debugFlag)
                    System.out.println(TLSHackConstants.HTTPSCERTFOUND+remoteServerCN);
                ssf = (CryptoTLSSocketManager) cnMap.get(remoteServerCN);
            }
            m_serverSocket = ssf.createServerSocket(getConnectionDetails().getLocalHost(), 0, timeout);
            return m_serverSocket;
        }


        /*
         * m_tempRemoteHost est le serveur TLS distant.
         */
        public void run()
        {
            try {
                final Socket localSocket = this.getServerSocket().accept();

                if (CryptoProxyServer.debugFlag)
                    System.out.println(TLSHackConstants.NEWPROXCONN +
                            m_tempRemoteHost + ":" + m_tempRemotePort);

                this.launchThreadPair(localSocket, remoteSocket,
                        localSocket.getInputStream(),
                        localSocket.getOutputStream(),
                        m_tempRemoteHost, m_tempRemotePort);
            } catch(IOException e) {
                e.printStackTrace(System.err);
            }
        }
    }

}