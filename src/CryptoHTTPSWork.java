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
 * Le client envoie d'abord un message CONNECT au port du proxy.
 * Le proxy accepte la connexion et répond avec un 200 OK,
 * Cela initie la file d'attente du client pour envoyer des données TLS au proxy.
 * Le proxy se contente de les transmettre au serveur identifié par le message CONNECT.
 *
 * L'API Java présente un défi particulier : elle permet aux sockets
 * d'être soit SSL soit non SSL, mais ne leur permet pas de changer leur
 * type en cours de route.Pour contourner ce problème, nous acceptons le CONNECT puis aveuglément
 * le reste du flux à travers une classe spéciale ProxyEngine (ProxySSLEngine) qui est instanciée pour
 * TLS.
 *
 * @author Team Crypto M1
 * @version 0.9
 */
public class CryptoHTTPSWork extends CryptoWork
{
    // Déclaration des variables communes à la classe
    private String m_tempRemoteHost;
    private int m_tempRemotePort;
    private final Pattern m_httpsConnectPattern;
    private final ProxyTLSEngine m_proxyTLSEngine;
    private final HashMap<String, CryptoTLSSocketManager> cnMap = new HashMap<String, CryptoTLSSocketManager>();

    /**
     * Constructeur de la classe
     * CryptoHTTPSocketManager => Classe pour créer un socket HTTP
     * CryptoTLSSocketManager => Classe pour créer un socket TLS
     * Crypofilter => Classe permettant de transférer les données d'une connexion TCP
     *
     */
    /**
     * Cosntructeur de la classe
     * @param plainSocketFactory Classe pour créer un socket HTTP
     * @param sslSocketFactory Classe pour créer un socket TLS
     * @param requestFilter Classe permettant de transférer les requêtes du client
     * @param responseFilter Classe permettant de transférer les réponses du serveur
     * @param localHost Adresse du proxy
     * @param localPort Port du proxy
     * @param timeout Timeout saisi au lancement de l'application
     * @throws IOException
     * @throws PatternSyntaxException
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

    /**
     * Fonction de démarrage du serveur proxy
     */
    public void run()
    {
        // Création d'un buffer d'une taille assez grande pour une connexion
        final byte[] buffer = new byte[TLSHackConstants.BUFFERCON];

        // Boucle infinie pour se mettre en écoute
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
                /**
                 * Exemple de ligne de requête du client
                 * CONNECT www.marmiton.org:443 HTTP/1.1
                 * Host: www.marmiton.org:443
                 * Proxy-Connection: keep-alive
                 * User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.79 Safari/537.36
                 */
                if (httpsConnectMatcher.find()) {
                    // On a bien un CONNECT
                    // Suppression des autres messages en clair du client
                    while (in.read(buffer, 0, in.available()) > 0) {
                    }
                    // Groupe 1 => Le serveur distant
                    final String remoteHost = httpsConnectMatcher.group(1);
                    // Groupe 2 => Le port
                    final int remotePort = Integer.parseInt(httpsConnectMatcher.group(2));

                    // Serveur distant et port
                    final String target = remoteHost + ":" + remotePort;

                    if (CryptoProxyServer.debugFlag)
                        System.out.println(TLSHackConstants.NEWPROXCONN + target);

                    m_tempRemoteHost = remoteHost;
                    m_tempRemotePort = remotePort;

                    // Récupération du "common name" du certificat du serveur distant
                    X509Certificate java_cert = null;
                    SSLSocket remoteSocket = null;
                    try {
                        // Création d'un socket pour récupérer le certificat du serveur distant
                        remoteSocket = (SSLSocket)
                                m_proxyTLSEngine.getSocketFactory().createClientSocket(remoteHost, remotePort);
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

                    if (CryptoProxyServer.debugFlag)
                        System.out.println(TLSHackConstants.REMOTESRVCN+cName);

                    //En théorie si on arrive jusque là, le socket a été initialisé dans le try
                    m_proxyTLSEngine.setRemoteSocket(remoteSocket);

                    // Création du serveurSocket de notre proxy.
                    ServerSocket localProxy = m_proxyTLSEngine.createServerSocket(cName,java_cert);

                    // Création d'un thread pour envoyer - recevoir les données depuis et vers le serveur distant.
                    new Thread(m_proxyTLSEngine, TLSHackConstants.THREADNAME).start();

                    try {Thread.sleep(10);} catch (Exception ignore) {}

                    // Création d'un nouveau socket pour la connexion du client vers notre proxy
                    final Socket sslProxySocket =
                            getSocketFactory().createClientSocket(
                                    getConnectionDetails().getLocalHost(),
                                    localProxy.getLocalPort());

                    // Création de deux threads pour le transfert de tout ce que l'on reçoit vers et depuis notre
                    // proxy.
                    new Thread(new CryptoStreamCopy(
                            in, sslProxySocket.getOutputStream()),
                            TLSHackConstants.THREADCOPYTO + target).start();
                    final OutputStream out = localSocket.getOutputStream();
                    new Thread(new CryptoStreamCopy(
                            sslProxySocket.getInputStream(), out),
                            TLSHackConstants.THREADCOPYFM + target).start();

                    // Envoie de la réponse HTTP : 200
                    // A partir de ce moment, les données transférées se feront avec TLS
                    sendClientResponse(out,"200 OK",remoteHost,remotePort);
                }
                else {
                    // La requête n'est pas un CONNECT, on ne fait rien.
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

    /**
     * Fonction pour envoyer une réponse au client
     * @param out Flux de type <code>OutputStream</code>
     * @param msg Message à envoyer
     * @param remoteHost Adresse du serveur distant
     * @param remotePort Port du serveur distant
     * @throws IOException
     */
    private void sendClientResponse(OutputStream out, String msg, String remoteHost, int remotePort) throws IOException {
        final StringBuffer response = new StringBuffer();
        response.append("HTTP/1.0 ").append(msg).append("\r\n");
        response.append("Host: " + remoteHost + ":" +
                remotePort + "\r\n");
        response.append("Proxy-agent: "+TLSHackConstants.PROXYHTTPNAME+"\r\n");
        response.append("\r\n");
        out.write(response.toString().getBytes());
        out.flush();
    }

    /**
     * Classe interne pour créer le coeur du ProxyTLS
     * Utilisé pour intercepter les données entre un client et un
     * serveur TLS distant, auquel le client adresse une requête.
     */
    private class ProxyTLSEngine extends CryptoWork {
        Socket remoteSocket = null;
        int timeout = 0;
        /*
         * Port number = 0 => Port alloué dynamiquement par la système
         */

        /**
         * Constructeur de la classe
         * @param socketFactory Gestionnaire de socket
         * @param requestFilter Classe permettant de transférer les requêtes du client
         * @param responseFilter Classe permettant de transférer les réponses du serveur
         * @throws IOException
         */
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

        /**
         * Fonction permettant de créer le socket du serveur
         * @param remoteServerCN CN du serveur distant
         * @param remoteServerCert Certificat du serveur distant
         * @return Un socket de type <code>ServerSocket</code>
         * @throws Exception
         */
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

        /**
         * Fonction exécutée par la classe CryptoHTTPSWork
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