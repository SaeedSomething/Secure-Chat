import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

public class ChatWebSocketServer extends WebSocketServer {

    private static final int KEY_SIZE = 2048;

    public ChatWebSocketServer(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection: " + conn.getRemoteSocketAddress());
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Closed connection: " + conn.getRemoteSocketAddress());
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        System.out.println("Message from " + conn.getRemoteSocketAddress() + ": " + message);

        if (message.startsWith("REQUEST_PUBLIC_KEY:")) {
            String username = message.substring("REQUEST_PUBLIC_KEY:".length());
            try {
                String publicKey = DataBaseHandler.getPublicKey(username);
                if (publicKey != null) {
                    String signedPublicKey = Server.signData(publicKey, Server.serverKeyPair.getPrivate());
                    conn.send("PUBLIC_KEY:" + publicKey + "." + signedPublicKey);
                } else {
                    conn.send("ERROR: User not found");
                }
            } catch (Exception e) {
                conn.send("ERROR: " + e.getMessage());
            }
        } else if (message.startsWith("MESSAGE:")) {
            for (WebSocket client : getConnections()) {
                if (client != conn) {
                    client.send(message);
                }
            }
        }
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("WebSocket server started successfully");
    }
}