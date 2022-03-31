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
import iaik.asn1.ObjectID;
import iaik.asn1.structures.Name;


/**
 * HTTPS proxy implementation.
 *
 * A HTTPS proxy client first send a CONNECT message to the proxy
 * port. The proxy accepts the connection responds with a 200 OK,
 * which is the client's queue to send SSL data to the proxy. The
 * proxy just forwards it on to the server identified by the CONNECT
 * message.
 *
 * The Java API presents a particular challenge: it allows sockets
 * to be either SSL or not SSL, but doesn't let them change their
 * stripes midstream. (In fact, if the JSSE support was stream
 * oriented rather than socket oriented, a lot of problems would go
 * away). To hack around this, we accept the CONNECT then blindly
 * proxy the rest of the stream through a special
 * ProxyEngine class (ProxySSLEngine) which is instantiated to
 * handle SSL.
 *
 * @author Srinivas Inguva
 */
public class CryptoHTTPSWork extends CryptoWork
{

    public static final String ACCEPT_TIMEOUT_MESSAGE = "Listen time out";

    private String m_tempRemoteHost;
    private int m_tempRemotePort;

    private final Pattern m_httpsConnectPattern;

    private final ProxyTLSEngine m_proxyTLSEngine;

    //NOTE: might be handy to use a bounded size cache..
    private final HashMap<String, CryptoTLSSocketManager> cnMap = new HashMap<String, CryptoTLSSocketManager>();

    public CryptoHTTPSWork(CryptoHTTPSocketManager plainSocketFactory,
                            CryptoTLSSocketManager sslSocketFactory,
                            CryptoFilter requestFilter,
                            CryptoFilter responseFilter,
                            String localHost,
                            int localPort,
                            int timeout)
            throws IOException, PatternSyntaxException
    {
        // We set this engine up for handling plain HTTP and delegate
        // to a proxy for HTTPS.
        super(plainSocketFactory,
                requestFilter,
                responseFilter,
                new CryptoConnDet(localHost, localPort, "", -1, false),
                timeout);

        m_httpsConnectPattern =
                Pattern.compile("^CONNECT[ \\t]+([^:]+):(\\d+).*\r\n\r\n",
                        Pattern.DOTALL);

        // When handling HTTPS proxies, we use our plain socket to
        // accept connections on. We suck the bit we understand off
        // the front and forward the rest through our proxy engine.
        // The proxy engine listens for connection attempts (which
        // come from us), then sets up a thread pair which pushes data
        // back and forth until either the server closes the
        // connection, or we do (in response to our client closing the
        // connection). The engine handles multiple connections by
        // spawning multiple thread pairs.

        assert sslSocketFactory != null;
        m_proxyTLSEngine = new ProxyTLSEngine(sslSocketFactory, requestFilter, responseFilter);

    }

    public void run()
    {
        // Should be more than adequate.
        final byte[] buffer = new byte[40960];

        while (true) {
            try {
                //Plaintext Socket with client (i.e. browser)
                final Socket localSocket = getServerSocket().accept();

                // Grab the first plaintext upstream buffer, which we're hoping is
                // a CONNECT message.
                final BufferedInputStream in =
                        new BufferedInputStream(localSocket.getInputStream(),
                                buffer.length);

                in.mark(buffer.length);

                // Read a buffer full.
                final int bytesRead = in.read(buffer);

                final String line =
                        bytesRead > 0 ?
                                new String(buffer, 0, bytesRead, TLSHackConstants.CRYPTOCHARSET) : "";

                final Matcher httpsConnectMatcher =
                        m_httpsConnectPattern.matcher(line);

                // 'grep' for CONNECT message and extract the remote server/port

                if (httpsConnectMatcher.find()) {//then we have a proxy CONNECT message!
                    // Discard any other plaintext data the client sends us:
                    while (in.read(buffer, 0, in.available()) > 0) {
                    }

                    final String remoteHost = httpsConnectMatcher.group(1);

                    // Must be a port number by specification.
                    final int remotePort = Integer.parseInt(httpsConnectMatcher.group(2));

                    final String target = remoteHost + ":" + remotePort;

                    if (CryptoProxyServer.debugFlag)
                        System.out.println("[HTTPSProxyEngine] Establishing a new HTTPS proxy connection to " + target);

                    m_tempRemoteHost = remoteHost;
                    m_tempRemotePort = remotePort;

                    X509Certificate java_cert = null;
                    SSLSocket remoteSocket = null;
                    try {
                        //Lookup the "common name" field of the certificate from the remote server:
                        remoteSocket = (SSLSocket)
                                m_proxyTLSEngine.getSocketFactory().createClientSocket(remoteHost, remotePort);
                        java_cert = (X509Certificate) remoteSocket.getSession().getPeerCertificates()[0];
                    } catch (IOException ioe) {
                        ioe.printStackTrace();
                        // Try to be nice and send a reasonable error message to client
                        sendClientResponse(localSocket.getOutputStream(),"504 Gateway Timeout",remoteHost,remotePort);
                        continue;
                    }
                    String serverCNJava = java_cert.getSubjectDN().getName();
                    System.out.println("Server SubjectDN : "+serverCNJava);
                    //Use the IAIK X509Cert class, because it has a simple way to get the CN
                    iaik.x509.X509Certificate cert = new iaik.x509.X509Certificate(java_cert.getEncoded());
                    Name n = (Name)cert.getSubjectDN();
                    String serverCN = n.getRDN(ObjectID.commonName);


                    if (CryptoProxyServer.debugFlag)
                        System.out.println("[HTTPSProxyEngine] Remote Server Cert CN= "+serverCN);

                    //We've already opened the socket, so might as well keep using it:
                    m_proxyTLSEngine.setRemoteSocket(remoteSocket);

                    //This is a CRUCIAL step:  we dynamically generate a new cert, based
                    // on the remote server's CN, and return a reference to the internal
                    // server socket that will make use of it.
                    ServerSocket localProxy = m_proxyTLSEngine.createServerSocket(serverCN,cert);

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
                            "Failed to determine proxy destination from message:");
                    System.err.println(line);
                    sendClientResponse(localSocket.getOutputStream(),"501 Not Implemented","localhost",
                            getConnectionDetails().getLocalPort());
                }
            }
            catch (InterruptedIOException e) {
                System.err.println(ACCEPT_TIMEOUT_MESSAGE);
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
     * Used to funnel data between a client (e.g. a web browser) and a
     * remote SSLServer, that the client is making a request to.
     *
     */
    private class ProxyTLSEngine extends CryptoWork {
        Socket remoteSocket = null;
        int timeout = 0;
        /*
         * NOTE: that port number 0, used below indicates a system-allocated,
         * dynamic port number.
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

        public final ServerSocket createServerSocket(String remoteServerCN, iaik.x509.X509Certificate remoteServerCert)
                throws Exception
        {

            assert remoteServerCN != null;

            CryptoTLSSocketManager ssf = null;

            if (cnMap.get(remoteServerCN) == null) {
                //Instantiate a NEW SSLSocketFactory with a cert that's based on the remote
                // server's Common Name
                System.out.println("[HTTPSProxyEngine] Creating a new certificate for "+remoteServerCN);
                ssf = new CryptoTLSSocketManager(remoteServerCN, remoteServerCert);
                cnMap.put(remoteServerCN, ssf);
            } else {
                if (CryptoProxyServer.debugFlag)
                    System.out.println("[HTTPSProxyEngine] Found cached certificate for "+remoteServerCN);
                ssf = (CryptoTLSSocketManager) cnMap.get(remoteServerCN);
            }
            m_serverSocket = ssf.createServerSocket(getConnectionDetails().getLocalHost(), 0, timeout);
            return m_serverSocket;
        }


        /*
         * localSocket.get[In|Out]putStream() is data that's (indirectly)
         * being read from / written to the client.
         *
         * m_tempRemoteHost is the remote SSL Server.
         */
        public void run()
        {
            try {
                final Socket localSocket = this.getServerSocket().accept();

                if (CryptoProxyServer.debugFlag)
                    System.out.println("[HTTPSProxyEngine] New proxy proxy connection to " +
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