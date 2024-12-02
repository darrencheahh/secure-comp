package comp3911.cwk2;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.StdErrLog;

public class AppServer {
  public static void main(String[] args) throws Exception {
    Log.setLog(new StdErrLog());

    ServletHandler servletHandler = new ServletHandler();
    servletHandler.addServletWithMapping(AppServlet.class, "/*");

    SessionHandler sessionHandler = new SessionHandler();
    sessionHandler.setHandler(servletHandler);

    Server server = new Server(8080);
    server.setHandler(sessionHandler);

    server.start();
    server.join();
  }
}

