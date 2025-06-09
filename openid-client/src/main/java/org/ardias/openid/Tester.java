package org.ardias.openid;


import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher;


public class Tester {

    public static void main(String...args) {

        Tester t = new Tester();
        try {
            t.run();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private void run() throws Exception {

        ServletContextHandler context = new ServletContextHandler();
        context.setInitParameter("javax.ws.rs.Application","org.ardias.openid.OpenIdApplication");
        context.addServlet(new ServletHolder(new HttpServletDispatcher()), "/");

        Server server = new Server(9000);
        server.setHandler(context);

        System.out.println(">>> STARTING JETTY SERVER, PRESS ANY KEY TO STOP");
        server.start();
        while (System.in.available() == 0) {
            Thread.sleep(1000);
        }
        server.stop();
        server.join();
    }
}
