import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Classe qui permet de créer des sockets non-TLS
 * @author Team crypto M1
 * @version 0.9
 */
public final class CryptoHTTPSocketManager implements CryptoSocketManager
{
    /**
     * Création du socket vers le serveur
     * @param localHost Adresse du Proxy
     * @param localPort Port du Proxy
     * @param timeout Timeout saisi au lancement du programme
     * @return Socket de type <code>ServerSocket</code>
     * @throws IOException
     */
    public final ServerSocket createServerSocket(String localHost,
                                                 int localPort,
                                                 int timeout)
            throws IOException
    {
        final ServerSocket socket =
                new ServerSocket(localPort, 50, InetAddress.getByName(localHost));

        socket.setSoTimeout(timeout);

        return socket;
    }

    /**
     * Création du socket vers le Client
     * @param remoteHost Adresse du Proxy
     * @param remotePort Port du Proxy
     * @return Socket de type <code>Socket</code>
     * @throws IOException
     */
    public final Socket createClientSocket(String remoteHost, int remotePort)
            throws IOException
    {
        return new Socket(remoteHost, remotePort);
    }
}

