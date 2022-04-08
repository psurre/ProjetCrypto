import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Classe principale du projet Crypto.
 * VM Option pour debugger : -Djavax.net.debug=ssl:handshake
 * @author Team Crypto M1
 * @version 0.9
 */

public class CryptoProxyServer
{
    /**
     * Paramètre pour activer ou non l'affichage des logs et debugger le code
     */
    public static boolean debugFlag = false;

    /**
     * Fonction principale de la classe
     * @param args Arguments passés à la classe main
     */
    public static void main(String[] args) {
        // Construction de l'objet proxy
        final CryptoProxyServer proxy = new CryptoProxyServer(args);
        // Démarrage effectif du proxy
        proxy.run();
    }
    /**
     * Affiche un message d'aide à l'utilisation de la classe main Java
     * @return null
     *
     */
    private Error printUsage() {
        System.err.println(
                "\n" +
                        "Usage: " +
                        "\n java CryptoProxyServer <options>" +
                        "\n" +
                        "\n Where options can include:" +
                        "\n" +
                        "\n   [-localHost <host name/ip>]  Default is "+TLSHackConstants.LOCALHOST +
                        "\n   [-localPort <port>]          Default is "+ TLSHackConstants.LOCALPORT +
                        "\n   [-keyStore <file>]           Key store details for" +
                        "\n   [-keyStorePassword <pass>]   certificates. Equivalent to" +
                        "\n   [-keyStoreType <type>]       javax.net.ssl.XXX properties" +
                        "\n   [-keyStoreAlias <alias>]     Default is "+ TLSHackConstants.CERTALIAS +
                        "\n   [-outputFile <filename>]     Default is stdout" +
                        "\n   [-v ]                        Verbose proxy output" +
                        "\n   [-h ]                        Print this message" +
                        "\n" +
                        "\n -outputFile specifies where the output from ProxyDataFilter will go." +
                        "\n By default, it is sent to stdout" +
                        "\n"
        );

        System.exit(1);
        return null;
    }

    /**
     * Fonction qui affiche un message d'erreur
     * @param s Chaine de caractères à afficher
     * @return Un message d'erreur
     */
    private Error printUsage(String s) {
        System.err.println("\n" + "Error: " + s);
        throw printUsage();
    }

    /**
     * Variable en charge de démarrer l'engine global.
     */
    private CryptoWork m_engine = null;

    /**
     * Constructeur de la classe
     * @param args Liste d'arguments passés à la fonction
     */
    private CryptoProxyServer (String[] args)
    {
        // Initialisation des variables
        CryptoFilter requestFilter = new CryptoFilter();
        CryptoFilter responseFilter = new CryptoFilter();
        int localPort = TLSHackConstants.LOCALPORT;
        String localHost = TLSHackConstants.LOCALHOST;
        int timeout = 0;

        // Initialisation des variables en fonction des arguments passés au programme
        try {
            for (int i=0; i<args.length; i++)
            {
                if (args[i].equals("-localHost")) {
                    localHost = args[++i];
                } else if (args[i].equals("-localPort")) {
                    localPort = Integer.parseInt(args[++i]);
                } else if (args[i].equals("-keyStore")) {
                    System.setProperty(TLSHackConstants.KEYSTORELIB,
                            args[++i]);
                } else if (args[i].equals("-keyStorePassword")) {
                    System.setProperty(TLSHackConstants.KEYSTOREPASSLIB,
                            args[++i]);
                } else if (args[i].equals("-keyStoreType")) {
                    System.setProperty(TLSHackConstants.KEYSTORETYPELIB,
                            args[++i]);
                } else if (args[i].equals("-keyStoreAlias")) {
                    System.setProperty(TLSHackConstants.KEYSTOREALIASLIB,
                            args[++i]);
                } else if (args[i].equals("-timeout")) {
                    timeout = Integer.parseInt(args[++i]) * 1000;
                } else if (args[i].equals("-v")) {
                    debugFlag = true;
                } else if (args[i].equals("-outputFile")) {
                    PrintWriter pw = new PrintWriter(new FileWriter(args[++i]), true);
                    requestFilter.setOutputPrintWriter(pw);
                    responseFilter.setOutputPrintWriter(pw);
                } else {
                    throw printUsage();
                }
            }
        }
        catch (Exception e) {
            throw printUsage();
        }
        // Contrôle sur la valeur de timeout
        if (timeout < 0) {
            throw printUsage("Timeout must be non-negative");
        }
        // Affichage du message de démarrage du proxy
        final StringBuffer startMessage = new StringBuffer();
        startMessage.append(TLSHackConstants.PROXYSTART +
                "\n   Local host:       " + localHost +
                "\n   Local port:       " + localPort);
        startMessage.append("\n   "+TLSHackConstants.TLSSETUP);
        System.err.println(startMessage);

        /**
         *  Création de la rootCA
         *  Si le fichier de la rootCA n'existe pas, on le crée.
         */
        File f = new File(TLSHackConstants.ROOTCAFILE);
        if(!f.isFile())
        {
            // Le fichier n'existe pas, on le crée
            try{
                CryptoX509.generateRootCA();
            } catch (Exception e){
                System.err.println(TLSHackConstants.ROOTCAERR);
                e.printStackTrace();
                System.exit(2);
            }
        }
        /**
         * Phase importante !!
         * Initialisation du m_engin avec le constructeur de la classe CryptoHTTPSWork qui hérite de CryptoWork
         */
        try {
            m_engine =
                    new CryptoHTTPSWork(new CryptoHTTPSocketManager(),
                            new CryptoTLSSocketManager(),
                            requestFilter,
                            responseFilter,
                            localHost,
                            localPort,
                            timeout);

            System.err.println(TLSHackConstants.PROXYLOAD + localPort);
        }
        catch (Exception e){
            System.err.println(TLSHackConstants.PROXYLOADERR);
            e.printStackTrace();
            System.exit(2);
        }
    }

    /**
     * Fonction de lancement du proxy HTTPS
     */
    public void run()
    {
        m_engine.run();
        System.err.println("Engine exited");
        System.exit(0);
    }
}
