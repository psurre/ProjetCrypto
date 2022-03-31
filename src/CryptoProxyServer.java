import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Base64;

/**
 * Classe principale du projet Crypto.
 *
 * @author Patrick Surre
 */

public class CryptoProxyServer
{
    public static boolean debugFlag = false;

    public static void main(String[] args) {
        final CryptoProxyServer proxy = new CryptoProxyServer(args);
        proxy.run();
    }

    private Error printUsage() {
        System.err.println(
                "\n" +
                        "Usage: " +
                        "\n java mitm.MITMProxyServer <options>" +
                        "\n" +
                        "\n Where options can include:" +
                        "\n" +
                        "\n   [-localHost <host name/ip>]  Default is localhost" +
                        "\n   [-localPort <port>]          Default is 8001" +
                        "\n   [-keyStore <file>]           Key store details for" +
                        "\n   [-keyStorePassword <pass>]   certificates. Equivalent to" +
                        "\n   [-keyStoreType <type>]       javax.net.ssl.XXX properties" +
                        "\n   [-keyStoreAlias <alias>]     Default is keytool default of 'mykey'" +
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
        // Default values.
        CryptoFilter requestFilter = new CryptoFilter();
        CryptoFilter responseFilter = new CryptoFilter();
        int localPort = 8001;
        String localHost = "localhost";

        int timeout = 0;
        String filename = null;

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

        if (timeout < 0) {
            throw printUsage("Timeout must be non-negative");
        }

        final StringBuffer startMessage = new StringBuffer();

        startMessage.append("Initializing SSL proxy with the parameters:" +
                "\n   Local host:       " + localHost +
                "\n   Local port:       " + localPort);
        startMessage.append("\n   (TLS setup could take a few seconds)");

        System.err.println(startMessage);

        try {
            m_engine =
                    new CryptoHTTPSWork(new CryptoHTTPSocketManager(),
                            new CryptoTLSSocketManager(),
                            requestFilter,
                            responseFilter,
                            localHost,
                            localPort,
                            timeout);

            System.err.println("Proxy initialized, listening on port " + localPort);
        }
        catch (Exception e){
            System.err.println("Could not initialize proxy:");
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
