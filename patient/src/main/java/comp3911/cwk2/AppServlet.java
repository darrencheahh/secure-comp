package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;


@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static final String AUTH_QUERY = "select * from user where username=? and password=?";
  private static final String SEARCH_QUERY = "select * from patient where surname=? collate nocase";

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    }
    catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    }
    catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private String validateAndSanitize(String input, String fieldName) {
    if (input == null || input.isEmpty()) {
        return null; // Return null for empty input
    }
    if ("Username".equals(fieldName)) {
        if (!input.matches("^[a-zA-Z0-9@.]+$")) {
            return null; // Invalid username
        }
    }
    if ("Surname".equals(fieldName)) {
        if (!input.matches("^[a-zA-Z]+$")) {
            return null; // Invalid surname
        }
    }
    return input.trim();
}


  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    preventCaching(response);

    String currentURI = request.getRequestURI();

    if (currentURI.equals("/")) {
        // Invalidate the session to log the user out
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate(); // Logs the user out
            System.out.println("User logged out successfully.");
        }

        // Redirect to the login page
        response.sendRedirect("/login");
    } else {
        // Handle the rest of the requests (like the details page)
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("authenticated") == null) {
            try {
                Template template = fm.getTemplate("login.html");
                template.process(null, response.getWriter());
                response.setContentType("text/html");
                response.setStatus(HttpServletResponse.SC_OK);
            } catch (TemplateException error) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        } else {
            response.sendRedirect("/");
        }

    try {
      HttpSession session = request.getSession();

      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
          throws ServletException, IOException {

      preventCaching(response);

      try {
          // Get form parameters
          String username = validateAndSanitize(request.getParameter("username"), "Username");
          String password = validateAndSanitize(request.getParameter("password"), "Password");
          String surname = validateAndSanitize(request.getParameter("surname"), "Surname");

          // Check for invalid or empty inputs
          if (username == null || password == null) {
              // Redirect to the invalid page if username or password is invalid or empty
              Template template = fm.getTemplate("invalid.html");
              template.process(null, response.getWriter());
              response.setContentType("text/html");
              response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
              return;
          }

          if (authenticated(username, password)) {
              HttpSession session = request.getSession();
              session.setAttribute("authenticated", true);

              // Get search results and merge with template
              Map<String, Object> model = new HashMap<>();
              if (surname != null && !surname.isEmpty()) {
                  List<Record> records = searchResults(surname);
                  model.put("records", records);
              }

              Template template = fm.getTemplate("details.html");
              template.process(model, response.getWriter());
              response.setContentType("text/html");
              response.setStatus(HttpServletResponse.SC_OK);
          } else {
              Template template = fm.getTemplate("invalid.html");
              template.process(null, response.getWriter());
              response.setContentType("text/html");
              response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          }

      } catch (Exception error) {
          error.printStackTrace();
          response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

    try {

      if (authenticated(username, password)) {
        // Get search results and merge with template
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());

      }
  }

  private boolean authenticated(String username, String password) throws SQLException {
    try (PreparedStatement pstmt = database.prepareStatement(AUTH_QUERY)) {
      pstmt.setString(1, username);
      pstmt.setString(2, password);
      try(ResultSet results = pstmt.executeQuery()){
        return results.next();
      }
    }
  }

  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();
    try (PreparedStatement pstmt = database.prepareStatement(SEARCH_QUERY)) {
      pstmt.setString(1, surname);
      try(ResultSet results = pstmt.executeQuery()){
        while (results.next()) {
          Record rec = new Record();
          rec.setSurname(results.getString(2));
          rec.setForename(results.getString(3));
          rec.setAddress(results.getString(4));
          rec.setDateOfBirth(results.getString(5));
          rec.setDoctorId(results.getString(6));
          rec.setDiagnosis(results.getString(7));
          records.add(rec);
        }
      }
    }
    return records;
  }

  private void preventCaching(HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0");
    response.setHeader("Pragma", "no-cache");
    response.setDateHeader("Expires", 0);

  private String generateCSRFToken() {
    return java.util.UUID.randomUUID().toString();

  }
}
