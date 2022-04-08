import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Classe de type <code>Runnable</code> qui copie depuis un flux d'entrée vers un flux de sortie
 * @author Team Crypto M1
 * @version 0.9
 */
public class CryptoStreamCopy implements Runnable
{
    private final InputStream m_in;
    private final OutputStream m_out;

    /**
     * Initialisation des flux d'entrée et de sortie
     * @param in Flux d'entrée
     * @param out Flux de sortie
     */
    public CryptoStreamCopy(InputStream in, OutputStream out) {
        m_in = in;
        m_out = out;
    }

    /**
     * Fonction qui démarre avec la classe
     */
    public void run() {
        final byte[] buffer = new byte[TLSHackConstants.BUFFERCON];

        try {
            short idle = 0;

            while (true) {
                final int bytesRead = m_in.read(buffer, 0, buffer.length);

                if (bytesRead ==  -1) {
                    break;
                }

                if (bytesRead == 0) {
                    idle++;
                } else {
                    m_out.write(buffer, 0, bytesRead);
                    idle = 0;
                }

                if (idle > 0) {
                    Thread.sleep(Math.max(idle * 200, 2000));
                }
            }
        } catch (IOException e) {
            e.printStackTrace(System.err);
        } catch (InterruptedException e) {
            e.printStackTrace(System.err);
        }

        try {
            m_out.close();
        } catch (IOException e) {
            e.printStackTrace(System.err);
        }

        try {
            m_in.close();
        } catch (IOException e) {
            e.printStackTrace(System.err);
        }
    }
}
