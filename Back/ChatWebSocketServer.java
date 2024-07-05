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

    // Store client public keys and WebSocket connections
    private ConcurrentHashMap<String, PublicKey> clientPublicKeys = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, WebSocket> clientConnections = new ConcurrentHashMap<>();

    private KeyPair serverKeyPair;

    public ChatWebSocketServer(int port) throws Exception {
        super(new InetSocketAddress(port));
        this.serverKeyPair = generateKeyPair();
    }

    // Generates a pair of RSA keys
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
    }

    // Encrypts a message with a given public key
    public static String encrypt(String message, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
    }

    // Decrypts a message with a given private key
    public static String decrypt(String message, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(message)));
    }

    // Signs a message with a given private key
    public static String sign(String message, PrivateKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(message.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    // Verifies a message signature with a given public key
    public static boolean verify(String message, String signatureStr, PublicKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
        return signature.verify(signatureBytes);
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection from " + conn.getRemoteSocketAddress().getAddress().getHostAddress());
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Closed connection to " + conn.getRemoteSocketAddress().getAddress().getHostAddress());
        // Remove the client from the maps
        clientPublicKeys.entrySet().removeIf(entry -> entry.getValue().equals(conn));
        clientConnections.entrySet().removeIf(entry -> entry.getValue().equals(conn));
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        try {
            String clientAddress = conn.getRemoteSocketAddress().getAddress().getHostAddress();

            // Assuming message format: "REGISTER:<client_id>:<base64_public_key>" for public key registration
            if (message.startsWith("REGISTER:")) {
                String[] parts = message.split(":");
                String clientId = parts[1];
                String publicKeyBase64 = parts[2];
                byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
                PublicKey clientPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                clientPublicKeys.put(clientId, clientPublicKey);
                clientConnections.put(clientId, conn);
                System.out.println("Registered public key for " + clientId + " from " + clientAddress);
                return;
            }

            // Assuming message format: "GET_PUBLIC_KEY:<client_id>"
            if (message.startsWith("GET_PUBLIC_KEY:")) {
                String clientId = message.split(":")[1];
                PublicKey publicKey = clientPublicKeys.get(clientId);
                if (publicKey != null) {
                    String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                    conn.send("PUBLIC_KEY:" + publicKeyBase64);
                } else {
                    conn.send("ERROR: Client ID not found");
                }
                return;
            }

            // Assuming message format: "MESSAGE:<from_client_id>:<to_client_id>:<base64_encrypted_message>:<base64_signature>"
            if (message.startsWith("MESSAGE:")) {
                String[] parts = message.split(":");
                String fromClientId = parts[1];
                String toClientId = parts[2];
                String encryptedMessageBase64 = parts[3];
                String signatureBase64 = parts[4];

                // Get the recipient's WebSocket connection
                WebSocket recipientConn = clientConnections.get(toClientId);
                if (recipientConn != null) {
                    // Forward the message to the recipient
                    recipientConn.send("MESSAGE:" + fromClientId + ":" + encryptedMessageBase64 + ":" + signatureBase64);
                } else {
                    conn.send("ERROR: Recipient not connected");
                }
                return;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        System.out.println("Binary message from " + conn.getRemoteSocketAddress().getAddress().getHostAddress());
        conn.send(message);
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("WebSocket server started on port: " + getPort());
    }

    public static void main(String[] args) throws Exception {
        int port = 8887; // Set your desired port
        ChatWebSocketServer server = new ChatWebSocketServer(port);
        server.start();
        System.out.println("ChatWebSocketServer started on port: " + port);
    }
}
