import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public abstract class CryptoWork implements Runnable {

    public static final String ACCEPT_TIMEOUT_MESSAGE = "Listen time out";
    private final CryptoFilter m_requestFilter;
    private final CryptoFilter m_responseFilter;
    private final CryptoConnDet m_connectionDetails;

    private final PrintWriter m_outputWriter;

    public final CryptoSocketManager m_socketFactory;
    protected ServerSocket m_serverSocket;

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

    //run() method from Runnable is implemented in subclasses

    public final ServerSocket getServerSocket() {
        return m_serverSocket;
    }

    protected final CryptoSocketManager getSocketFactory() {
        return m_socketFactory;
    }

    protected final CryptoConnDet getConnectionDetails() {
        return m_connectionDetails;
    }


    /*
     * Launch a pair of threads that:
     * (1) Copy data sent from the client to the remote server
     * (2) Copy data sent from the remote server to the client
     *
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