package de.rub.nds.jsse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionHandler implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Socket applicationSocket;

    public ConnectionHandler(Socket socket) {
        applicationSocket = socket;
    }

    @Override
    public void run() {
        LOGGER.debug("New thread started");
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(applicationSocket.getInputStream()));
            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(applicationSocket.getOutputStream()));
            String line = "";
            
            while ((line = br.readLine()) != null) {
                LOGGER.debug(line);
                bw.write("ack");
                bw.flush();
            }
        } catch (IOException ex) {
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        } finally {
            try {
                applicationSocket.close();
            } catch (final IOException ex) {
                LOGGER.debug(ex.getLocalizedMessage(), ex);
            }
        }
    }
}