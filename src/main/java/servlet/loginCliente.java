package servlet;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import dao.ClienteJpaController;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import util.JwtUtil;
import org.mindrot.jbcrypt.BCrypt;

@WebServlet(name = "loginCliente", urlPatterns = {"/logincliente"})
public class loginCliente extends HttpServlet {

    private final EntityManagerFactory emf = Persistence.createEntityManagerFactory("com.mycompany_Pry02_war_1.0-SNAPSHOTPU");
    private final ClienteJpaController clienteDAO = new ClienteJpaController(emf);
    private final Gson gson = new Gson();

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json;charset=UTF-8");

        try (PrintWriter out = response.getWriter()) {

            // Leer JSON del cuerpo POST
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = request.getReader()) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            }

            JsonObject json = gson.fromJson(sb.toString(), JsonObject.class);
            if (json == null || !json.has("user") || !json.has("pass")) {
                out.println("{\"resultado\":\"error\",\"mensaje\":\"Faltan parámetros\"}");
                return;
            }

            String userParam = json.get("user").getAsString();
            String pass = json.get("pass").getAsString();

            int codiClie;
            try {
                codiClie = Integer.parseInt(userParam);
            } catch (NumberFormatException e) {
                out.println("{\"resultado\":\"error\", \"mensaje\":\"Usuario inválido\"}");
                return;
            }

            // Obtener hash bcrypt almacenado (hash de pass+user)
            String hashedPassword = clienteDAO.obtenerPasswordPorCodigo(codiClie);
            if (hashedPassword == null) {
                out.println("{\"resultado\":\"error\",\"mensaje\":\"Usuario no encontrado\"}");
                return;
            }

            // Concatenar pass + user
            String passConUser = pass + userParam;

            // Validar contraseña con bcrypt
            boolean valido = BCrypt.checkpw(passConUser, hashedPassword);

            if (valido) {
                try {
                    String token = JwtUtil.generarToken(userParam);
                    request.getSession().setAttribute("usuario", userParam);
                    out.println("{\"resultado\":\"ok\",\"token\":\"" + token + "\"}");
                } catch (Exception e) {
                    e.printStackTrace();
                    out.println("{\"resultado\":\"error\",\"mensaje\":\"Error al generar token\"}");
                }
            } else {
                out.println("{\"resultado\":\"error\",\"mensaje\":\"Usuario o contraseña incorrectos\"}");
            }

        } catch (Exception e) {
            e.printStackTrace();
            response.getWriter().println("{\"resultado\":\"error\",\"mensaje\":\"Error interno del servidor\"}");
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    public String getServletInfo() {
        return "Servlet para login de cliente con bcrypt y JWT";
    }
}
