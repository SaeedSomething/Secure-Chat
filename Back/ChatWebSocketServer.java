import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.json.JSONException;
import org.json.JSONObject;

public class ChatWebSocketServer extends WebSocketServer {

    // A map to keep track of chat session participants
    private static Map<Integer, Set<WebSocket>> chatSessions = new ConcurrentHashMap<>();
    // A map to keep track of which chat session a WebSocket connection belongs to
    private static Map<WebSocket, Integer> connectionChatSessionMap = new ConcurrentHashMap<>();

    public ChatWebSocketServer(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection from " + conn.getRemoteSocketAddress());
        
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Closed connection to " + conn.getRemoteSocketAddress());
        // Remove the connection from all chat sessions it was a part of
        Integer sessionId = connectionChatSessionMap.remove(conn);
        if (sessionId != null) {
            Set<WebSocket> participants = chatSessions.get(sessionId);
            if (participants != null) {
                participants.remove(conn);
                if (participants.isEmpty()) {
                    chatSessions.remove(sessionId);
                }
            }
        }
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        try {
            JSONObject jsonMessage = new JSONObject(message);
            String type = jsonMessage.getString("type");

            if ("chat".equals(type)) {
                int connectionId = jsonMessage.getInt("connectionId"); // Use connectionId instead of sessionId
                String chatMessage = jsonMessage.getString("message");

                // Relay the message to the appropriate chat session
                sendMessageToChatSession(connectionId, chatMessage, conn);
            } else if ("join".equals(type)) {
                int connectionId = jsonMessage.getInt("connectionId");
                addParticipantToChatSession(connectionId, conn);
            } else {
                System.out.println("Unknown message type: " + type);
            }
        } catch (JSONException e) {
            e.printStackTrace();
            System.out.println("Invalid message format: " + message);
        }
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("WebSocket Server started!");
    }

    public void addParticipantToChatSession(int sessionId, WebSocket conn) {
        chatSessions.putIfAbsent(sessionId, Collections.newSetFromMap(new ConcurrentHashMap<>()));
        chatSessions.get(sessionId).add(conn);
        connectionChatSessionMap.put(conn, sessionId);
        System.out.println("Added participant to chat session: " + sessionId);
    }

    public void sendMessageToChatSession(int sessionId, String message) {
        sendMessageToChatSession(sessionId, message, null);
    }

    public void sendMessageToChatSession(int sessionId, String message, WebSocket sender) {
        if (chatSessions.containsKey(sessionId)) {
            for (WebSocket conn : chatSessions.get(sessionId)) {
                if (conn != sender) {
                    conn.send(message);
                }
            }
        }
    }
}
