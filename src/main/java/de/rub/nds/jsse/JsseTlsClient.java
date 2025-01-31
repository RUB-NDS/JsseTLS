package de.rub.nds.jsse;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
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
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class JsseTlsClient {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    private String[] cipherSuites = null;
    private final SSLContext sslContext;
    private SSLSocket clientSocket;
    private boolean shutdown;
    boolean closed = true;
    private static final String PATH_TO_JKS = "rsa2048.jks";
    private static final String JKS_PASSWORD = "password";
    private static final String ALIAS = "1";
    private static final int PORT = 4433;
    private static final String HOST = "127.0.0.1";
    private final int port;
    private final String host;
    private volatile boolean initialized;

    public JsseTlsClient(KeyStore keyStore, String password, String protocol, int port, String host) throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        this.port = port;
        this.host = host;

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, password.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, new TrustManager[]{new InsecureTrustManager()}, new SecureRandom());

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
        String host;

        switch (args.length) {
            case 5:
                host = args[0];
                port = Integer.parseInt(args[1]);
                path = args[2];
                password = args[3];
                alias = args[4];
                break;
            case 0:
                host = HOST;
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
        JsseTlsClient tlsServer = new JsseTlsClient(ks, password, "TLS", port, host);
        tlsServer.start();
    }

    public void start() {
        try {
            preSetup();
            try {
                LOGGER.info("Connecting on port " + port + "...\n");
                clientSocket.startHandshake();
                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                reader.read();
            } catch (IOException ex) {
                LOGGER.debug(ex.getLocalizedMessage(), ex);
            }
        } catch (IOException ex) {
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        } finally {
            try {
                if (clientSocket != null && !clientSocket.isClosed()) {
                    clientSocket.close();
                    clientSocket = null;
                }
            } catch (IOException e) {
                LOGGER.debug(e);
            }
            LOGGER.info("Shutdown complete");
        }
    }

    private void preSetup() throws SocketException, IOException {
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        clientSocket = (SSLSocket) socketFactory.createSocket(host, port); 
        clientSocket.setReuseAddress(false);
        
        // TODO:
        // if (cipherSuites != null) {
        // ((SSLServerSocket)
        // serverSocket).setEnabledCipherSuites(cipherSuites);
        // }
        
        initialized = true;
        LOGGER.debug("Presetup successful");
    }

    public void shutdown() {
        this.shutdown = true;
        LOGGER.debug("Shutdown signal received");
        try {
            if (!clientSocket.isClosed()) {
                clientSocket.close();
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
        if (clientSocket != null) {
            return clientSocket.getLocalPort();
        } else {
            return port;
        }
    }
    
    private class InsecureTrustManager implements X509TrustManager {  
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
