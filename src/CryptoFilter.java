import java.io.PrintWriter;
/**
 * Cette classe est utilisée pour enregistrer les données qui vont et viennent sur une connexion TCP
 * La sortie est dirigée vers un PrintWriter, dont la valeur par défaut est System.out.
 *
 * NOTE: Cette fonction pourrait être enrichie pour modifier les requêtes HTTP transmises.
 *
 * @author Team Crypto M1
 * @version 0.9
 */
public class CryptoFilter {
    /**
     * Variable pour le flux en sortie.
     */
    private PrintWriter m_out = new PrintWriter(System.out, true);

    /**
     * Fixer la sortie du printWriter
     * @param outputPrintWriter Un objet de type <code>PrintWriter</code>
     */
    public void setOutputPrintWriter(PrintWriter outputPrintWriter)  {
        m_out.flush();
        m_out = outputPrintWriter;
    }

    /**
     * Récupérer le flux de sortie
     * @return Un objet de type <code>PrintWriter</code>
     */
    public PrintWriter getOutputPrintWriter() {
        return m_out;
    }

    /**
     * Fonction de création d'un handle sur la connexion
     * @param connectionDetails Détails de la connexion
     * @param buffer Buffer pour la lecture du flux
     * @param bytesRead Nombre d'octets à lire
     * @return Null
     * @throws java.io.IOException
     */
    public byte[] handle(CryptoConnDet connectionDetails,
                         byte[] buffer, int bytesRead)
            throws java.io.IOException
    {
        final StringBuffer stringBuffer = new StringBuffer();

        boolean inHex = false;

        for(int i=0; i<bytesRead; i++) {
            final int value = (buffer[i] & 0xFF);

            // Si c'est de l'ASCII, on peut l'écrire comme un caractère.
            if (value == '\r' || value == '\n' ||
                    (value >= ' ' && value <= '~')) {
                if (inHex) {
                    stringBuffer.append(']');
                    inHex = false;
                }
                stringBuffer.append((char)value);
            }
            else { // Sinon, on écrit sa valeur
                if (!inHex) {
                    stringBuffer.append('[');
                    inHex = true;
                }
                if (value <= 0xf) {
                    stringBuffer.append("0");
                }
                stringBuffer.append(Integer.toHexString(value).toUpperCase());
            }
        }

        m_out.println("------ "+ connectionDetails.getDescription() +
                " ------");
        m_out.println(stringBuffer);
        return null;
    }

    /**
     * Message à l'ouverture de la connexion
     * @param connectionDetails Détails de la connexion
     */
    public void connectionOpened(CryptoConnDet connectionDetails) {
        m_out.println("--- " +  connectionDetails.getDescription() +
                " opened --");
    }
    /**
     * Message à la fermeture de la connexion
     * @param connectionDetails Détails de la connexion
     */
    public void connectionClosed(CryptoConnDet connectionDetails) {
        m_out.println("--- " +  connectionDetails.getDescription() +
                " closed --");
    }
}