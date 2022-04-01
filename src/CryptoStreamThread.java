import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.SocketException;

/**
 * Copie les octets d'un InputStream vers un OutputStream.  Utilise un
 * ProxyDataFilter pour enregistrer le contenu de manière appropriée.
 *
 */
public class CryptoStreamThread implements Runnable
{
    // Pour des raisons de simplicité, les filtres adoptent une approche orientée tampon.
    // Cela signifie qu'ils s'arrêtent tous aux limites du tampon. Notre tampon
    // est énorme, donc nous ne devrions pas poser de problème, mais le réseau peut le faire en nous envoyant des fragments de messages.

    private final CryptoConnDet m_connectionDetails;
    private final InputStream m_in;
    private final OutputStream m_out;
    private final CryptoFilter m_filter;
    private final PrintWriter m_outputWriter;

    public CryptoStreamThread(CryptoConnDet connectionDetails,
                        InputStream in, OutputStream out,
                        CryptoFilter filter,
                        PrintWriter outputWriter)
    {
        m_connectionDetails = connectionDetails;
        m_in = in;
        m_out = out;
        m_filter = filter;
        m_outputWriter = outputWriter;

        final Thread t =
                new Thread(this,
                        TLSHackConstants.THREADFILTER +
                                m_connectionDetails.getDescription());

        try {
            m_filter.connectionOpened(m_connectionDetails);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        t.start();
    }

    public void run() {
        try {
            byte[] buffer = new byte[TLSHackConstants.BUFFERSIZE];

            while (true) {
                final int bytesRead = m_in.read(buffer, 0, TLSHackConstants.BUFFERSIZE);

                if (bytesRead == -1) {
                    break;
                }


                final byte[] newBytes =
                        m_filter.handle(m_connectionDetails, buffer, bytesRead);

                m_outputWriter.flush();

                if (newBytes != null) {
                    m_out.write(newBytes);
                } else {
                    m_out.write(buffer, 0, bytesRead);
                }
            }
        } catch (SocketException e) {
            // On ne renvoie pas d'erreur sur les erreurs de Socket
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        try {
            m_filter.connectionClosed(m_connectionDetails);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        m_outputWriter.flush();

        // Fin lorsque le stream d'entrée est clos.
        try {
            m_out.close();
        } catch (Exception e) {
        }

        try {
            m_in.close();
        } catch (Exception e) {
        }
    }
}