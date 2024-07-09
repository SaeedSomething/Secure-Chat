import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;

import javax.crypto.Cipher;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class ChatWebSocketServer extends WebSocketServer {

    private static final int KEY_SIZE = 2048;
    private ConcurrentHashMap<String, WebSocket> userConnections = new ConcurrentHashMap<>();

    public ChatWebSocketServer(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection: " + conn.getRemoteSocketAddress());
        // You can add code to authenticate the user here if needed
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Closed connection: " + conn.getRemoteSocketAddress());
        userConnections.values().remove(conn);
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        System.out.println("Message from " + conn.getRemoteSocketAddress() + ": " + message);

        if (message.startsWith("REGISTER:")) {
            String username = message.substring("REGISTER:".length());
            userConnections.put(username, conn);
        } else if (message.startsWith("REQUEST_PUBLIC_KEY:")) {
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
            String[] parts = message.split(":", 3);
            int connectionId = Integer.parseInt(parts[1]);
            String encryptedMessage = parts[2];

            try {
                List<Integer> participantIds = DataBaseHandler.getParticipants(connectionId);
                for (Integer userId : participantIds) {
                    String username = DataBaseHandler.getUsername(userId);
                    WebSocket client = userConnections.get(username);
                    if (client != null && client != conn) {
                        client.send("MESSAGE:" + connectionId + ":" + encryptedMessage);
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
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
