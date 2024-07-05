import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.KeyGenerator;

import javax.crypto.SecretKey;

import org.json.JSONObject;

public class Server {
    public static KeyPair serverKeyPair;

    public static void main(String[] args) throws Exception {
        // Generate server key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        serverKeyPair = keyGen.generateKeyPair();

        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/signup", new SignUpHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/getPublicKey", new PublicKeyHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
        System.out.println("HTTP Server started on port 8000");

        // Start WebSocket server on a separate thread
        new Thread(() -> {
            try {
                ChatWebSocketServer wsServer = new ChatWebSocketServer(9000);
                wsServer.start();
                System.out.println("WebSocket Server started on port 9000");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    static class SignUpHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String[] params = requestBody.split("&");

                String username = null;
                String password = null;
                String email = null;
                String ip = null;
                String publicKey = null;

                for (String param : params) {
                    String[] keyValue = param.split("=");
                    switch (keyValue[0]) {
                        case "username":
                            username = keyValue[1];
                            break;
                        case "password":
                            password = keyValue[1];
                            break;
                        case "email":
                            email = keyValue[1];
                            break;
                        case "ip":
                            ip = keyValue[1];
                            break;
                        case "publickey":
                            publicKey = keyValue[1];
                            break;
                    }
                }

                if (username != null && password != null && email != null && ip != null && publicKey != null) {
                    try {
                        // Generate symmetric key
                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(256);
                        SecretKey symKey = keyGen.generateKey();
                        String symKeyString = Base64.getEncoder().encodeToString(symKey.getEncoded());

                        DataBaseHandler.addUser(username, password, email, ip, publicKey, symKeyString);

                        String response = "User registered successfully. Symmetric key: " + symKeyString;
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
                    String response = "Error: Missing parameters";
                    exchange.sendResponseHeaders(400, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method not allowed
            }
        }
    }

    static class PublicKeyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String[] params = requestBody.split("&");

                String username = null;
                for (String param : params) {
                    String[] keyValue = param.split("=");
                    if ("username".equals(keyValue[0])) {
                        username = keyValue[1];
                        System.out.println("Username: " + username);
                        break;
                    }
                }

                if (username != null) {
                    try {
                        String publicKey = DataBaseHandler.getPublicKey(username);
                        System.out.println("Public key: " + publicKey);
                        if (publicKey != null) {
                            String signedPublicKey = signData(publicKey, serverKeyPair.getPrivate());
                            String response = publicKey + "." + signedPublicKey;
                            exchange.sendResponseHeaders(200, response.length());
                            OutputStream os = exchange.getResponseBody();
                            os.write(response.getBytes());
                            os.close();
                        } else {
                            String response = "Error: User not found";
                            exchange.sendResponseHeaders(404, response.length());
                            OutputStream os = exchange.getResponseBody();
                            os.write(response.getBytes());
                            os.close();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        String response = "Error: " + e.getMessage();
                        exchange.sendResponseHeaders(500, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    }
                } else {
                    String response = "Error: Missing username parameter";
                    exchange.sendResponseHeaders(400, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method not allowed
            }
        }
    }

    public static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String[] params = requestBody.split("&");

                String username = null;
                String password = null;

                for (String param : params) {
                    String[] keyValue = param.split("=");
                    switch (keyValue[0]) {
                        case "username":
                            username = keyValue.length > 1 ? keyValue[1] : null;
                            break;
                        case "password":
                            password = keyValue.length > 1 ? keyValue[1] : null;
                            break;
                    }
                }

                if (username != null && password != null) {
                    try {
                        boolean isValidUser = DataBaseHandler.verifyUser(username, password);

                        JSONObject responseJson = new JSONObject();
                        if (isValidUser) {
                            responseJson.put("status", "success");
                            responseJson.put("message", "Login successful");
                            responseJson.put("serverPublicKey",
                                    Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()));
                        } else {
                            responseJson.put("status", "error");
                            responseJson.put("message", "Invalid username or password");
                        }

                        String response = responseJson.toString();
                        exchange.sendResponseHeaders(isValidUser ? 200 : 401, response.length());
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
                    String response = "Error: Missing parameters";
                    exchange.sendResponseHeaders(400, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method not allowed
            }
        }
    }
}