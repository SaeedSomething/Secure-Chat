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

    public static void main(String[] args) {
        try {
            // addUser("asd", "password124", "exampleasdasd@example.com", "127.0.0.1");
            System.out.println(authenticateUser("asd", "password124"));
        } catch (Exception e) {
            e.printStackTrace();
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

    public static boolean authenticateUser(String username, String password) throws Exception {
        Connection con = null;
        try {
            con = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);

            // Retrieve the salt and password hash from the database
            String query = "SELECT p.pass_hash, p.salt FROM public.\"user\" u JOIN public.\"password\" p ON u.pass_id = p.id WHERE u.username = ?";
            PreparedStatement pst = con.prepareStatement(query);
            pst.setString(1, username);
            ResultSet rs = pst.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("pass_hash");
                int salt = rs.getInt("salt");

                // Hash the provided password with the retrieved salt
                String hashedPassword = hashPassword(password, salt);

                // Compare the hashed password with the stored hash
                return storedHash.equals(hashedPassword);
            } else {
                return false; // User not found
            }
        } catch (SQLException | NoSuchAlgorithmException e) {
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

    public static void addUser(String username, String password, String email, String ip, byte[] publicKeyBytes,
            byte[] keyBytes)
            throws Exception {
        PreparedStatement pstUser = null;
        PreparedStatement pstPass = null;
        PreparedStatement pstRole = null;
        Connection con = null;
        try {
            con = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
            con.setAutoCommit(false);

            // Generate salt
            SecureRandom random = new SecureRandom();
            int salt = random.nextInt();

            // Hash the password with SHA-256 and salt
            String passHash = hashPassword(password, salt);

            // Insert into password table
            String insertPasswordSQL = "INSERT INTO public.\"password\" (pass_hash, salt) VALUES (?, ?) RETURNING id";
            PreparedStatement pstPassword = con.prepareStatement(insertPasswordSQL);
            pstPassword.setString(1, passHash);
            pstPassword.setInt(2, salt);
            ResultSet rsPassword = pstPassword.executeQuery();

            if (rsPassword.next()) {
                int passId = rsPassword.getInt(1);

                // Insert into roles table
                String insertRoleSQL = "INSERT INTO public.roles (cancreategroup, isadmin) VALUES (?, ?) RETURNING rid";
                pstRole = con.prepareStatement(insertRoleSQL);
                pstRole.setBoolean(1, false); // Default role permissions
                pstRole.setBoolean(2, false); // Default role permissions
                ResultSet rsRole = pstRole.executeQuery();

                if (rsRole.next()) {
                    int roleId = rsRole.getInt(1);

                    // Insert into user table
                    String userQuery = "INSERT INTO public.\"user\" (username, creation_date, pass_id, email, rid, last_ipaddr, key, publickey) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                    pstUser = con.prepareStatement(userQuery);
                    pstUser.setString(1, username);
                    pstUser.setTimestamp(2, new Timestamp(System.currentTimeMillis()));
                    pstUser.setInt(3, passId);
                    pstUser.setString(4, email);
                    pstUser.setInt(5, roleId);
                    pstUser.setString(6, ip);
                    pstUser.setBytes(7, keyBytes);
                    pstUser.setBytes(8, publicKeyBytes);

                    pstUser.executeUpdate();

                    // Commit transaction
                    con.commit();

                    System.out.println("User added successfully!");
                    // Send the key to the user
                    System.out.println("Symmetric Key (Base64): " + Base64.getEncoder().encodeToString(keyBytes));

                    rsRole.close();
                    pstRole.close();
                    rsPassword.close();
                    pstPassword.close();
                    pstUser.close();
                } else {
                    throw new SQLException("Failed to insert role, no ID obtained.");
                }
            } else {
                throw new SQLException("Failed to insert password, no ID obtained.");
            }

        } catch (SQLException | NoSuchAlgorithmException e) {
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

    private static String hashPassword(String password, int salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Integer.toString(salt).getBytes());
        byte[] hashedPassword = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedPassword);
    }
}