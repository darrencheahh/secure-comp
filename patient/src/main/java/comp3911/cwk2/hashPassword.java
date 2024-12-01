package comp3911.cwk2;

import org.mindrot.jbcrypt.BCrypt;
import java.sql.*;


public class hashPassword {
    private static final String database_connection = "jdbc:sqlite:db.sqlite3";
  
    public static void main(String[] args) {
        hashPasswords();
    }
  
    public static void hashPasswords() {
      try (Connection connection = DriverManager.getConnection("jdbc:sqlite:db.sqlite3")) {
        String databaseQuery = "SELECT username, password FROM user";
        Statement statement = connection.createStatement();
        ResultSet results = statement.executeQuery("select * from user");
        
        while (results.next()) {
          String username = results.getString(1);
          String password = results.getString(2);
  
          String hashed = BCrypt.hashpw(password, BCrypt.gensalt());  // hash the password using salt
          String updateQuery = "UPDATE user SET password = ? WHERE username = ?";  // send hashed password back to database
  
          try (PreparedStatement updateStmt = connection.prepareStatement(updateQuery)) {
            updateStmt.setString(1, bcryptHash);
            updateStmt.setString(2, username);
            updateStmt.executeUpdate();
          }
        }
        System.out.println("Passwords have been hashed!");
      }
      catch (SQLException error) {
        System.out.println(error.getMessage());
      }
    }
  }