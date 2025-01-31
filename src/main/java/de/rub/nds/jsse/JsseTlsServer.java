package de.rub.nds.jsse;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class JsseTlsServer {

    private static final Logger LOGGER = LogManager.getLogger();
        
    private String[] cipherSuites = null;
    private final SSLContext sslContext;
    private ServerSocket serverSocket;
    private boolean shutdown;
    boolean closed = true;
    private static final String PATH_TO_JKS = "rsa2048.jks";
    private static final String JKS_PASSWORD = "password";
    private static final String ALIAS = "1";
    private static final int PORT = 4433;
    private final int port;
    private volatile boolean initialized;

    public JsseTlsServer(KeyStore keyStore, String password, String protocol, int port) throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        this.port = port;

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, password.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, trustManagers, new SecureRandom());

        cipherSuites = sslContext.getServerSocketFactory().getSupportedCipherSuites();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Provider: " + sslContext.getProvider());
            LOGGER.debug("Supported cipher suites ("
                    + sslContext.getServerSocketFactory().getSupportedCipherSuites().length + ")");
            for (String c : sslContext.getServerSocketFactory().getSupportedCipherSuites()) {
                LOGGER.debug(" " + c);
            }
        }
    }
    
    public static void main(String[] args) throws Exception {
        System.setProperty("java.security.debug", "ssl");
        String path, ecPath = null;
        String password, ecPassword = null;
        String alias, ecAlias = null;
        boolean useBouncyCastleProvider = false;
        int port;

        switch (args.length) {
            case 5:
            case 4:
                port = Integer.parseInt(args[0]);
                path = args[1];
                password = args[2];
                alias = args[3];
                if(args.length == 5 && args[4].equalsIgnoreCase("BC")) {
                    useBouncyCastleProvider = true;
                }
                break;
            case 0:
                path = PATH_TO_JKS;
                password = JKS_PASSWORD;
                alias = ALIAS;
                port = PORT;
                break;
            default:
                System.out.println("Usage (run with): java -jar [name].jar [port] [jks-path] "
                        + "[password] [alias] [BC]");
                return;
        }
        
        if(useBouncyCastleProvider) {
            Provider provider = new BouncyCastleProvider();
            Security.insertProviderAt(provider, 1);
        }
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(path), password.toCharArray());
        JsseTlsServer tlsServer = new JsseTlsServer(ks, password, "TLS", port);
        tlsServer.start();
    }

    public void start() {
        try {
            preSetup();
            closed = false;
            while (!shutdown) {
                try {
                    LOGGER.info("Listening on port " + port + "...\n");
                    final Socket socket = serverSocket.accept();
                    if (socket != null) {
                        ConnectionHandler ch = new ConnectionHandler(socket);
                        Thread t = new Thread(ch);
                        t.start();
                    }
                } catch (IOException ex) {
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
            closed = true;
        } catch (IOException ex) {
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        } finally {
            try {
                if (serverSocket != null && !serverSocket.isClosed()) {
                    serverSocket.close();
                    serverSocket = null;
                }
            } catch (IOException ex) {
                LOGGER.debug(ex.getLocalizedMessage(), ex);
            }
            LOGGER.info("Shutdown complete");
        }
    }

    private void preSetup() throws SocketException, IOException {
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
        serverSocket = serverSocketFactory.createServerSocket(port);
        serverSocket.setReuseAddress(true);
        
        // Enable client authentication
        ((javax.net.ssl.SSLServerSocket) serverSocket).setNeedClientAuth(false);
        
        // TODO:
        // if (cipherSuites != null) {
        // ((SSLServerSocket)
        // serverSocket).setEnabledCipherSuites(cipherSuites);
        // }
        
        initialized = true;
        LOGGER.debug("Presetup successful");
    }

    public void shutdown() {
        LOGGER.debug("Shutdown signal received");
        this.shutdown = true;
        try {
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException ex) {
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
    }

    public String[] getCipherSuites() {
        return cipherSuites;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public int getPort() {
        if (serverSocket != null) {
            return serverSocket.getLocalPort();
        } else {
            return port;
        }
    }
}
