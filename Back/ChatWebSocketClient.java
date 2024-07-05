import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;

public class ChatWebSocketClient extends WebSocketClient {

    private KeyPair keyPair;
    private String clientId;

    public ChatWebSocketClient(URI serverURI, String clientId) throws Exception {
        super(serverURI);
        this.keyPair = generateKeyPair();
        this.clientId = clientId;
    }

    // Generates a pair of RSA keys
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
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
    public void onOpen(ServerHandshake handshakedata) {
        System.out.println("Connected to server");

        // Register public key with the server
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        send("REGISTER:" + clientId + ":" + publicKeyBase64);
    }

    @Override
    public void onMessage(String message) {
        try {
            if (message.startsWith("PUBLIC_KEY:")) {
                // Handle public key response
                String publicKeyBase64 = message.split(":")[1];
                byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                System.out.println("Received public key: " + publicKey);

                // Example of sending a message to another client (e.g., clientB)
                String recipientId = "clientB";
                String plainTextMessage = "Hello, Client B!";
                String encryptedMessage = encrypt(plainTextMessage, publicKey);
                String signature = sign(plainTextMessage, keyPair.getPrivate());

                send("MESSAGE:" + clientId + ":" + recipientId + ":" + encryptedMessage + ":" + signature);
            } else if (message.startsWith("MESSAGE:")) {
                // Handle incoming encrypted message
                String[] parts = message.split(":");
                String fromClientId = parts[1];
                String encryptedMessageBase64 = parts[2];
                String signatureBase64 = parts[3];

                String decryptedMessage = decrypt(encryptedMessageBase64, keyPair.getPrivate());

                PublicKey senderPublicKey = ...; // Retrieve the sender's public key from some storage

                if (verify(decryptedMessage, signatureBase64, senderPublicKey)) {
                    System.out.println("Received message from " + fromClientId + ": " + decryptedMessage);
                } else {
                    System.out.println("Invalid signature from " + fromClientId);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        System.out.println("Disconnected from server");
    }

    @Override
    public void onError(Exception ex) {
        ex.printStackTrace();
    }

    public static void main(String[] args) throws Exception {
        String serverUri = "ws://localhost:8887";
        String clientId = "clientA";

        ChatWebSocketClient client = new ChatWebSocketClient(new URI(serverUri), clientId);
        client.connectBlocking();

        // Request public key of another client (e.g., clientB)
        client.send("GET_PUBLIC_KEY:clientB");
    }
}
