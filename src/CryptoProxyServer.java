import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Classe principale du projet Crypto.
 *
 * @author Team Crypto
 */

public class CryptoProxyServer
{
    public static boolean debugFlag = false;

    public static void main(String[] args) {
        // Construction de l'objet proxy
        final CryptoProxyServer proxy = new CryptoProxyServer(args);
        // Démarrage effectif du proxy
        proxy.run();
    }

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
                        "\n   [-keyStoreAlias <alias>]     Default is "+ TLSHackConstants.DEFAULT_ALIAS +
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

    private Error printUsage(String s) {
        System.err.println("\n" + "Error: " + s);
        throw printUsage();
    }

    private CryptoWork m_engine = null;

    private CryptoProxyServer (String[] args)
    {
        // Initialisation des variables
        CryptoFilter requestFilter = new CryptoFilter();
        CryptoFilter responseFilter = new CryptoFilter();
        int localPort = TLSHackConstants.LOCALPORT;
        String localHost = TLSHackConstants.LOCALHOST;

        int timeout = 0;
        String filename = null;
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
        // Création de la rootCA
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
        try {
            // Appel à la classe CryptoHTTPSWork pour créer le proxy
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

    public void run()
    {
        m_engine.run();
        System.err.println("Engine exited");
        System.exit(0);
    }
}
