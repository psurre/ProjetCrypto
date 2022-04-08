import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.SocketException;

/**
 * Copie les octets d'un InputStream vers un OutputStream.  Utilise un
 * <code>ProxyDataFilter</code> pour enregistrer le contenu de manière appropriée.
 * @author Team Crypto M1
 * @version 0.9
 */
public class CryptoStreamThread implements Runnable
{
    // Pour des raisons de simplicité, les filtres adoptent une approche orientée tampon.
    // Cela signifie qu'ils s'arrêtent tous aux limites du tampon. Notre tampon
    // est énorme, donc nous ne devrions pas avoir de problèmes.

    private final CryptoConnDet m_connectionDetails;
    private final InputStream m_in;
    private final OutputStream m_out;
    private final CryptoFilter m_filter;
    private final PrintWriter m_outputWriter;

    /**
     * Constructeur de classe
     * @param connectionDetails Détails d'une connexion
     * @param in Flux d'entrée
     * @param out Flux de sortie
     * @param filter Filtre de sortie pour afficher des informations
     * @param outputWriter Objet de type <code>PrintWriter</code>
     */
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
    /**
     * Fonction qui démarre avec la classe
     */
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
            e.printStackTrace(System.err);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        try {
            m_filter.connectionClosed(m_connectionDetails);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        m_outputWriter.flush();

        try {
            m_out.close();
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        try {
            m_in.close();
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
}