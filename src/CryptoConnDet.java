/**
 * Fonction permettant de retourner les informations d'une connexion et de voir si le TLS est activé.
 *
 * @author Team Crypto M1
 * @version 0.9
 *
 */
public class CryptoConnDet {

    /**
     * Initialisation des variables
     */
    private final int m_hashCode;
    private String m_localHost;
    private int m_localPort;
    private String m_remoteHost;
    private int m_remotePort;
    private boolean m_isSecure;

    /**
     * Constructeur de la classe.
     * @param localHost Proxy Intercepteur TLS
     * @param localPort Port d'écoute du Proxy Intercepteur TLS
     * @param remoteHost Serveur distant que le client souhaite contacter
     * @param remotePort Port sur le serveur distant
     * @param isSecure <code>true</code> si le TLS est actif
     */
    public CryptoConnDet(String localHost, int localPort,
                             String remoteHost, int remotePort,
                             boolean isSecure)
    {
        m_localHost = localHost.toLowerCase();
        m_localPort = localPort;
        m_remoteHost = remoteHost.toLowerCase();
        m_remotePort = remotePort;
        m_isSecure = isSecure;
        /**
         * Constitution du hash avec
         * Le hash de l'adresse du proxy XOR l'adresse du serveur distant
         *  XOR le port du proxy XOR le port du serveur XOR
         *  un poivre en fonction de l'activation ou non du TLS
         */
        m_hashCode =
                m_localHost.hashCode() ^
                        m_remoteHost.hashCode() ^
                        m_localPort ^
                        m_remotePort ^
                        (m_isSecure ? TLSHackConstants.ALEAHASH : 0);
    }

    /**
     * Fonction pour écriture les connexions montées par le Proxy
     * @return La ligne de détail d'une connexion.
     */
    public String getDescription() {
        return
                m_localHost + ":" + m_localPort + "->" +
                        m_remoteHost + ":" + m_remotePort;
    }

    /**
     *
     * @return <code>true</code> si le TLS est activé
     */
    public boolean isSecure() {
        return m_isSecure;
    }

    /**
     *
     * @return Le nom du serveur distant
     */
    public String getRemoteHost() {
        return m_remoteHost;
    }

    /**
     *
     * @return Le nom du Proxy
     */
    public String getLocalHost() {
        return m_localHost;
    }

    /**
     *
     * @return Le port du serveur distant
     */
    public int getRemotePort() {
        return m_remotePort;
    }

    /**
     *
     * @return Le port du Proxy
     */
    public int getLocalPort() {
        return m_localPort;
    }

    /**
     * Fonction qui permet de comparer des objets.
     *
     * @param other Une valeur d'<code>Object</code>
     * @return <code>true</code> => <code>other</code>est égal à l'objet en cours
     *
     */
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }

        if (!(other instanceof CryptoConnDet)) {
            return false;
        }

        final CryptoConnDet otherConnectionDetails = (CryptoConnDet)other;

        return
                hashCode() == otherConnectionDetails.hashCode() &&
                        getLocalPort() == otherConnectionDetails.getLocalPort() &&
                        getRemotePort() == otherConnectionDetails.getRemotePort() &&
                        isSecure() == otherConnectionDetails.isSecure() &&
                        getLocalHost().equals(otherConnectionDetails.getLocalHost()) &&
                        getRemoteHost().equals(otherConnectionDetails.getRemoteHost());
    }

    /**
     *
     * @return <code>int</code> Valeur du hash
     */
    public final int hashCode() {
        return m_hashCode;
    }

}