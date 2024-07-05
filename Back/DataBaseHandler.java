import java.io.*;
import java.sql.*;
import java.time.Instant;
import java.util.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DataBaseHandler {
    static String DB_URL = "jdbc:postgresql://localhost:5432/postgres";
    static String DB_USERNAME = "postgres";
    static String DB_PASSWORD = "167294381";

    // public static void main(String[] args) {
    // try {
    // // addUser("asd", "password124", "exampleasdasd@example.com", "127.0.0.1");
    // System.out.println(verifyUser("asd", "password124"));
    // } catch (Exception e) {
    // e.printStackTrace();
    // }
    // }

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