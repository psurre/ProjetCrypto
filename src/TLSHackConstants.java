public interface TLSHackConstants {

    // Constantes Connexion
    String PROXYHOST = "google.com";
    Integer PORTECOUTE = 8080;
    Integer PORTREMOTE = 443;

    // Constantes Générales
    String CRYPTOCHARSET = "UTF-8";

    // Constantes Crypto
    String ALGO = "RSA";
    String KEYLENGTH = "4096";
    String KEYSTORELIB = "javax.net.ssl.keyStore";
    String KEYSTOREPASSLIB = "javax.net.ssl.keyStorePassword";
    String KEYSTORETYPELIB = "javax.net.ssl.keyStoreType";
    String KEYSTOREALIASLIB = "javax.net.ssl.keyStoreAlias";
    String DEFAULT_ALIAS = "mykey";
    String FICHIERCLEPRIVE = "key.priv";
    String FICHIERCLEPUBLIC = "key.pub";
    String KEYSTORETYPE = "PKCS12";
    String KEYSTOREFILE = "fortknox.ks";
    String KEYSTOREPASS = "bW90MnBAc3NlSkFWQQ==";

    // Constantes Log
    String PROXYSTART = "************* Démarrage du serveur Proxy ***************";
    String PROXPORT = "====> Port d'écoute : ";
    String CLIENTREQUEST =  "Requête du client ===> proxy";
    String PROXYREQUEST = "Requête proxy ===> ";
    String HOSTREQUESTFORMAT = "CONNECT";
    String ERREURUSAGE = "Les paramètres fournis sont incorrect\nUsage: java TLSHack <port>";
    String ERREURGEN = "Une erreur a été levée par le programme";

}
