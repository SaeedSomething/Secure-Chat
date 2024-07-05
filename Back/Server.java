import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Server {

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/signup", new SignUpHandler());
        server.createContext("/login", new LoginHandler());
        ExecutorService executor = Executors.newFixedThreadPool(10);
        server.setExecutor(executor);
        server.start();
        System.out.println("HTTP Server started on port 8000");

        // Start WebSocket server in a separate thread
        Thread wsThread = new Thread(() -> {
            try {
                WebSocketServer wsServer = new WebSocketServer(9000);
                wsServer.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        wsThread.start();
    }

    static class SignUpHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                byte[] requestBody = exchange.getRequestBody().readAllBytes();
                String requestBodyStr = new String(requestBody, StandardCharsets.UTF_8);
                String[] params = requestBodyStr.split("&");
                String username = params[0].split("=")[1];
                String password = params[1].split("=")[1];
                String email = params[2].split("=")[1];
                String ip = params[3].split("=")[1];
                byte[] publicKeyBytes = Base64.getDecoder().decode(params[4].split("=")[1]);

                try {
                    // Generate a symmetric key
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256);
                    SecretKey secretKey = keyGen.generateKey();
                    byte[] keyBytes = secretKey.getEncoded();
                    String symmetricKeyBase64 = Base64.getEncoder().encodeToString(keyBytes);

                    // Add user to database
                    DataBaseHandler.addUser(username, password, email, ip, publicKeyBytes, keyBytes);

                    // Send the key to the user
                    String response = "User registered successfully! Symmetric Key: " + symmetricKeyBase64;
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    String response = "Error: " + e.getMessage();
                    exchange.sendResponseHeaders(500, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                byte[] requestBody = exchange.getRequestBody().readAllBytes();
                String requestBodyStr = new String(requestBody, StandardCharsets.UTF_8);
                String[] params = requestBodyStr.split("&");
                String username = params[0].split("=")[1];
                String password = params[1].split("=")[1];

                try {
                    boolean authenticated = DataBaseHandler.authenticateUser(username, password);
                    String response;
                    if (authenticated) {
                        response = "User authenticated successfully!";
                        exchange.sendResponseHeaders(200, response.length());
                    } else {
                        response = "Authentication failed!";
                        exchange.sendResponseHeaders(401, response.length());
                    }
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    String response = "Error: " + e.getMessage();
                    exchange.sendResponseHeaders(500, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }
}
