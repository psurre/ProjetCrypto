public interface TLSHackConstants {

    // Constantes Générales
    String CRYPTOCHARSET = "UTF-8";
    int BUFFERSIZE = 65536;
    int LOCALPORT = 8001;
    String LOCALHOST = "localhost";

    // Constantes Crypto
    String KEYSTORELIB = "javax.net.ssl.keyStore";
    String KEYSTOREPASSLIB = "javax.net.ssl.keyStorePassword";
    String KEYSTORETYPELIB = "javax.net.ssl.keyStoreType";
    String KEYSTOREALIASLIB = "javax.net.ssl.keyStoreAlias";
    String DEFAULT_ALIAS = "mykey";
    String BC_PROVIDER = "BC";
    String KEY_ALGORITHM = "RSA";
    int KEY_SIZE = 2048;
    String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";
    String TLSSTANDARD = "TLSv1.2";
    String ROOTCACN = "CN=localhost";
    String ROOTCAKSTYPE = "PKCS12";
    String ROOTCAFILE = "localhost.pfx";
    String ROOTCACERT = "localhost.cer";
    String ROOTCACERTPEM = "localhost.pem";
    String ROOTCAKSPASS = "bW90MnBAc3NlSkFWQQ==";
    String ROOTCAERR = "[CryptoProxyServer] Erreur à la création de la Root CA !!";

    // Constantes Log
    String PROXYSTART = "************* Démarrage du serveur Proxy ***************";
    String PROXYLOAD = "==> Proxy actif et en écoute sur le port : ";
    String PROXYLOADERR = " !!!! Le proxy n'a pas pu s'activer !!!!";
    String TLSSETUP = "Veuillez patienter pendant l'initialisation TLS.";
    String ACCEPTTIMEOUTMSG = "Temps en écoute dépassé";
    String THREADFILTER = "Thread de transfert pour :";
    String HTTPSCERTCREATE = "[CryptoHTTPSWork] Creation d'un nouveau certificat pour ";
    String HTTPSCERTFOUND = "[CryptoHTTPSWork] Certificat trouvé dans le cache pour ";
    String NEWPROXCONN = "[CryptoHTTPSWork] Nouvelle connexion proxy vers ";
    String TOCLIENTERR = "504 Gateway Timeout";
    String REMOTESRVCN = "[CryptoHTTPSWork] Serveur distant Cert CN=";
    String PKERROR = "!!! Pas de clé privée dans le keystore !!!";
    String PKFORMAT = "[Info] Format de la clé privée : ";
    String NEWCERT = "[Info] Nouveau Certifcat : ";
    String KEYGENERR = "[CryptoX509] Erreur de génération de clef ! ";
    String CERTSUCCESS = "[CryptoX509] Certificat généré avec succès !";
    String PROVIDERERR = "[CryptoX509] Erreur de provider ! ";
    String OPEXCEPT = "[CryptoX509] Erreur de provider ! ";
    String CERTERREXCEPT = "[CryptoX509] Erreur de transformation du certificat au format X509 ! ";
    String PROXFAILEDTO = "Impossible de trouver la destination pour le message: ";
    String MSG501 = "501 non implémenté";
}
