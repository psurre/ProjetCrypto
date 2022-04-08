import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Classe mère de CryptoHTTPSocketManager
 *
 * @author Team Crypto 1
 * @version 0.9
 */
public interface CryptoSocketManager
{
    ServerSocket createServerSocket(String localHost, int localPort,
                                    int timeout)
            throws IOException;

    Socket createClientSocket(String remoteHost, int remotePort)
            throws IOException;
}

