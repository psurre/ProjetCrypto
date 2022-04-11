import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
/**
 * Classe mère du moteur proxy HTTPS
 * @author Team Crypto M1
 * @version 0.9
 */
public abstract class CryptoWork implements Runnable {

    // Déclaration des variables locales
    private final CryptoFilter m_requestFilter;
    private final CryptoFilter m_responseFilter;
    private final CryptoConnDet m_connectionDetails;
    private final PrintWriter m_outputWriter;
    public final CryptoSocketManager m_socketFactory;
    protected ServerSocket m_serverSocket;

    // Constructeur de la classe
    public CryptoWork(CryptoSocketManager socketFactory,
                       CryptoFilter requestFilter,
                       CryptoFilter responseFilter,
                       CryptoConnDet connectionDetails,
                       int timeout)
            throws IOException
    {
        m_socketFactory = socketFactory;
        m_requestFilter = requestFilter;
        m_responseFilter = responseFilter;
        m_connectionDetails = connectionDetails;

        m_outputWriter = requestFilter.getOutputPrintWriter();

        m_serverSocket =
                m_socketFactory.createServerSocket(
                        connectionDetails.getLocalHost(),
                        connectionDetails.getLocalPort(),
                        timeout);
    }

    public final ServerSocket getServerSocket() {
        return m_serverSocket;
    }

    protected final CryptoSocketManager getSocketFactory() {
        return m_socketFactory;
    }

    protected final CryptoConnDet getConnectionDetails() {
        return m_connectionDetails;
    }

    /**
     * Fonctionne pour démarrer une paire de thread :
     * 1) Copie les données envoyées du client vers le serveur distant
     * 2) Copie les données envoyées par le serveur distant vers le client
     * @param localSocket socket ouvert pour le client
     * @param remoteSocket socket ouvert pour le serveur distant
     * @param localInputStream flux de données en entrée
     * @param localOutputStream flux de données en sortie
     * @param remoteHost serveur distant
     * @param remotePort port du serveur distant
     * @throws IOException
     */
    protected final void launchThreadPair(Socket localSocket, Socket remoteSocket,
                                          InputStream localInputStream,
                                          OutputStream localOutputStream,
                                          String remoteHost,
                                          int remotePort)
            throws IOException
    {

        new CryptoStreamThread(new CryptoConnDet(
                m_connectionDetails.getLocalHost(),
                localSocket.getPort(),
                remoteHost,
                remoteSocket.getPort(),
                m_connectionDetails.isSecure()),
                localInputStream,
                remoteSocket.getOutputStream(),
                m_requestFilter,
                m_outputWriter);

        new CryptoStreamThread(new CryptoConnDet(
                remoteHost,
                remoteSocket.getPort(),
                m_connectionDetails.getLocalHost(),
                localSocket.getPort(),
                m_connectionDetails.isSecure()),
                remoteSocket.getInputStream(),
                localOutputStream,
                m_responseFilter,
                m_outputWriter);
    }
}