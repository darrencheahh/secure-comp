package comp3911.cwk2;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Base64;

public class HashingPassword {

    private static final String db_connection = "jdbc:sqlite:db.sqlite3";

    public static void main(String[] args) {
        hashPasswords();
    }

    public static void hashPasswords() {
        try (Connection connection = DriverManager.getConnection(db_connection)) {
            
            // query for username and password
            String selectQuery = "SELECT username, password FROM user";
            Statement selectStmt = connection.createStatement();
            ResultSet results = selectStmt.executeQuery(selectQuery);

            // iterate through each user record
            while (results.next()) {
                String username = results.getString("username");
                String plaintextPassword = results.getString("password");

                // hash the password using SHA-256
                String hashedPassword = hashWithSHA256(plaintextPassword);

                // update the database with the hashed password
                String updateQuery = "UPDATE user SET password = ? WHERE username = ?";
                try (PreparedStatement updateStmt = connection.prepareStatement(updateQuery)) {
                    updateStmt.setString(1, hashedPassword);
                    updateStmt.setString(2, username);
                    updateStmt.executeUpdate();
                }
            }

            System.out.println("Passwords have been hashed.");
        } catch (SQLException | NoSuchAlgorithmException error) {
            error.printStackTrace();
        }
    }

    public static String hashWithSHA256(String password) throws NoSuchAlgorithmException {
        // get an instance of SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // compute the hash
        byte[] hashedBytes = digest.digest(password.getBytes());

        // encode the hash into a readable format (Base64)
        return Base64.getEncoder().encodeToString(hashedBytes);
    }
}
