import java.io.*;
import java.sql.*;
import java.util.*;
import java.time.Instant;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class DataBaseHandler {
    static String DB_URL = "jdbc:postgresql://localhost:5432/postgres";

    static String DB_USERNAME ;
    static String DB_PASSWORD ;
    static {
        DB_USERNAME = System.getenv("DB_USERNAME");
        DB_PASSWORD = System.getenv("DB_PASSWORD");

        if (DB_USERNAME == null || DB_PASSWORD == null) {
            throw new RuntimeException("Database credentials are not set in environment variables.");
        }
    }

    public static String getUsername(int userId) throws SQLException {
        String query = "SELECT username FROM public.\"user\" WHERE uid = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
                PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("username");
            }
        }
        return null; // User not found
    }

    public static int getUserId(String username) throws SQLException {
        String query = "SELECT uid FROM public.\"user\" WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
                PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("uid");
            }
        }
        return -1; // User not found
    }

    public static int createChatSession(int user1Id, int user2Id) throws SQLException {
        String query = "INSERT INTO public.\"Connection\" (\"type\", \"creation_time\", \"name\") VALUES (false, NOW(), 'P2P') RETURNING id";
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
                PreparedStatement stmt = conn.prepareStatement(query)) {
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }
        return -1; // Failed to create chat session
    }

    public static void addParticipant(int connectionId, int userId) throws SQLException {
        String query = "INSERT INTO public.participants (cid, uid) VALUES (?, ?)";
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
                PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setInt(1, connectionId);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
    }

    public static JSONArray getChatSessions(int userId) throws SQLException {
        String query = """
                    SELECT c.id, c.\"name\", u.username
                    FROM public.participants p
                    JOIN public.\"Connection\" c ON p.cid = c.id
                    JOIN public.\"user\" u ON p.uid = u.uid
                    WHERE p.cid IN (
                        SELECT cid FROM public.participants WHERE uid = ?
                    )
                """;

        JSONArray chatSessions = new JSONArray();
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
                PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();

            // This map will hold chat session details, where the key is the chat session ID
            Map<Integer, JSONObject> chatSessionMap = new HashMap<>();

            while (rs.next()) {
                int chatSessionId = rs.getInt("id");
                String chatSessionName = rs.getString("name");
                String participantUsername = rs.getString("username");

                // If the chat session is not already in the map, add it
                if (!chatSessionMap.containsKey(chatSessionId)) {
                    JSONObject chatSession = new JSONObject();
                    chatSession.put("id", chatSessionId);
                    chatSession.put("name", chatSessionName);
                    chatSession.put("participants", new JSONArray());
                    chatSessionMap.put(chatSessionId, chatSession);
                }

                // Add the participant username to the chat session
                JSONObject chatSession = chatSessionMap.get(chatSessionId);
                chatSession.getJSONArray("participants").put(participantUsername);
            }

            // Add all chat sessions to the final JSON array
            for (JSONObject chatSession : chatSessionMap.values()) {
                chatSessions.put(chatSession);
            }
        }

        return chatSessions;
    }

    public static List<Integer> getParticipants(int connectionId) throws SQLException {
        String query = "SELECT uid FROM public.participants WHERE cid = ?";
        List<Integer> participantIds = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
                PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setInt(1, connectionId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                participantIds.add(rs.getInt("uid"));
            }
        }
        return participantIds;
    }

    public static void updateRolesForUsername(String username, boolean[] roles) {
        String query = "UPDATE public.roles SET cancreategroup = ?, isadmin = ? " +
                "WHERE rid = (SELECT rid FROM public.\"user\" WHERE username = ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
                PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setBoolean(1, roles[0]);
            stmt.setBoolean(2, roles[1]);
            stmt.setString(3, username);
            stmt.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean[] getRolesForUsername(String username) {
        String query = "SELECT r.cancreategroup, r.isadmin FROM public.\"user\" u " +
                "JOIN public.roles r ON u.rid = r.rid " +
                "WHERE u.username = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
                PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    boolean canCreateGroup = rs.getBoolean("cancreategroup");
                    boolean isAdmin = rs.getBoolean("isadmin");
                    return new boolean[] { canCreateGroup, isAdmin };
                } else {
                    System.out.println("User not found or no roles associated with the user.");
                    return null;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String getPublicKey(String username) throws Exception {
        Connection con = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);

        try {
            String selectSQL = "SELECT publickey FROM \"user\" WHERE username = ?";
            PreparedStatement ps = con.prepareStatement(selectSQL);
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                return rs.getString("publickey");
            } else {
                return null;
            }
        } finally {
            con.close();
        }
    }

    public static void updateUserRoles(boolean[] roles, String username) throws Exception {
        if (roles.length != 2) {
            throw new IllegalArgumentException("Roles array must have exactly 2 elements");
        }

        Connection con = null;
        try {
            con = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
            con.setAutoCommit(false);

            // Retrieve rid from user table
            String getRoleIdSQL = "SELECT rid FROM public.\"user\" WHERE username = ?";
            PreparedStatement pstGetRoleId = con.prepareStatement(getRoleIdSQL);
            pstGetRoleId.setString(1, username);
            ResultSet rsRoleId = pstGetRoleId.executeQuery();

            if (rsRoleId.next()) {
                int roleId = rsRoleId.getInt(1);

                // Update roles table
                String updateRoleSQL = "UPDATE public.roles SET cancreategroup = ?, isadmin = ? WHERE rid = ?";
                PreparedStatement pstUpdateRole = con.prepareStatement(updateRoleSQL);
                pstUpdateRole.setBoolean(1, roles[0]);
                pstUpdateRole.setBoolean(2, roles[1]);
                pstUpdateRole.setInt(3, roleId);
                pstUpdateRole.executeUpdate();

                // Commit transaction
                con.commit();

                System.out.println("User roles updated successfully!");

                pstUpdateRole.close();
                rsRoleId.close();
                pstGetRoleId.close();
            } else {
                throw new SQLException("User not found with the specified username.");
            }

        } catch (SQLException e) {
            if (con != null) {
                try {
                    con.rollback();
                } catch (SQLException rollbackEx) {
                    rollbackEx.printStackTrace();
                }
            }
            e.printStackTrace();
            throw e;
        } finally {
            if (con != null) {
                try {
                    con.close();
                } catch (SQLException closeEx) {
                    closeEx.printStackTrace();
                }
            }
        }
    }

    public static boolean verifyUser(String username, String password) throws Exception {
        Connection con = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);

        try {
            // Retrieve password hash and salt
            String selectSQL = "SELECT p.pass_hash, p.salt FROM \"user\" u JOIN password p ON u.pass_id = p.id WHERE u.username = ?";
            PreparedStatement ps = con.prepareStatement(selectSQL);
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("pass_hash");
                int salt = rs.getInt("salt");

                // Hash the provided password
                String hashedPassword = hashPassword(password, salt);

                // Compare the hashed password with the stored hash
                return storedHash.equals(hashedPassword);
            } else {
                return false;
            }
        } finally {
            con.close();
        }
    }

    public static void addUser(String username, String password, String email, String ip, String publicKey,
            String symKey) throws Exception {
        Connection con = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
        con.setAutoCommit(false);

        try {
            // Generate salt
            SecureRandom random = new SecureRandom();
            int salt = random.nextInt();

            // Hash password
            String hashedPassword = hashPassword(password, salt);

            // Insert into password table
            String insertPasswordSQL = "INSERT INTO password (pass_hash, salt) VALUES (?, ?) RETURNING id";
            PreparedStatement psPassword = con.prepareStatement(insertPasswordSQL);
            psPassword.setString(1, hashedPassword);
            psPassword.setInt(2, salt);
            ResultSet rsPassword = psPassword.executeQuery();
            rsPassword.next();
            int passwordId = rsPassword.getInt(1);

            // Insert into roles table
            String insertRoleSQL = "INSERT INTO roles (cancreategroup, isadmin) VALUES (false, false) RETURNING rid";
            PreparedStatement psRole = con.prepareStatement(insertRoleSQL);
            ResultSet rsRole = psRole.executeQuery();
            rsRole.next();
            int roleId = rsRole.getInt(1);

            // Insert into user table
            String insertUserSQL = "INSERT INTO \"user\" (username, creation_date, pass_id, email, rid, last_ipaddr, publickey, symetrickey) VALUES (?, NOW(), ?, ?, ?, ?, ?, ?)";
            PreparedStatement psUser = con.prepareStatement(insertUserSQL);
            psUser.setString(1, username);
            psUser.setInt(2, passwordId);
            psUser.setString(3, email);
            psUser.setInt(4, roleId);
            psUser.setString(5, ip);
            psUser.setBytes(6, publicKey.getBytes());
            psUser.setBytes(7, symKey.getBytes());
            psUser.executeUpdate();

            con.commit();
        } catch (SQLException e) {
            con.rollback();
            throw e;
        } finally {
            con.close();
        }
    }

    private static String hashPassword(String password, int salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Integer.toString(salt).getBytes());
        byte[] hashedPassword = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedPassword);
    }
}