package net.ctrdn.stuba.psip.swswitch.adminportal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ResourceServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String requestUrl = request.getRequestURI();
        if (requestUrl.equals("/")) {
            requestUrl = "/status.html";
        }
        String requestFileName = "/net/ctrdn/stuba/psip/swswitch/adminportal" + requestUrl;
        InputStream is = getClass().getResourceAsStream(requestFileName);
        if (is != null) {
            response.setStatus(HttpServletResponse.SC_OK);
            String fileNameLc = requestFileName.toLowerCase();
            if (fileNameLc.endsWith(".html")) {
                response.setContentType("text/html");
            } else if (fileNameLc.endsWith(".js")) {
                response.setContentType("text/javascript");
            } else if (fileNameLc.endsWith(".css")) {
                response.setContentType("text/css");
            } else if (fileNameLc.endsWith(".png")) {
                response.setContentType("image/png");
            } else if (fileNameLc.endsWith(".svg")) {
                response.setContentType("image/svg");
            } else if (fileNameLc.endsWith(".eot")) {
                response.setContentType("font/opentype");
            } else if (fileNameLc.endsWith(".ttf")) {
                response.setContentType("application/x-font-ttf");
            } else if (fileNameLc.endsWith(".woff")) {
                response.setContentType("application/x-font-woff");
            } else {
                throw new ServletException("Unknown file type");
            }
            if (fileNameLc.endsWith(".html")) {
                byte[] data = this.preprocess(is, requestUrl);
                response.getOutputStream().write(data, 0, data.length);
            } else {
                byte[] buffer = new byte[1024];
                while (is.available() > 0) {
                    int rd = is.read(buffer, 0, buffer.length);
                    response.getOutputStream().write(buffer, 0, rd);
                }
            }
        } else {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().println("404 Not Found");
        }
    }

    private byte[] preprocess(InputStream is, String requestUrl) throws IOException, ServletException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (is.available() > 0) {
            int rd = is.read(buffer, 0, buffer.length);
            baos.write(buffer, 0, rd);
        }
        String htmlString = baos.toString("UTF-8");
        htmlString = htmlString.replaceAll("%portal_header_html%", this.preprocessHeader(requestUrl));
        htmlString = htmlString.replaceAll("%portal_footer_html%", this.getTemplate("/template/footer.tpl.html"));
        return htmlString.getBytes("UTF-8");
    }

    private String preprocessHeader(String requestUrl) throws IOException, ServletException {
        String mainMenuHtml = "<ul class=\"nav nav-pills\" style=\"margin-top: 10px; margin-bottom: 20px;\">";
        mainMenuHtml += "<li " + ((requestUrl.equals("/status.html") ? "class=\"active\"" : "")) + "><a href=\"/status.html\"><span class=\"glyphicon glyphicon-eye-open\"></span> Switch Status</a></li>";
        mainMenuHtml += "<li " + ((requestUrl.equals("/interface.html") ? "class=\"active\"" : "")) + "><a href=\"/interface.html\"><span class=\"glyphicon glyphicon-resize-horizontal\"></span> Interfaces</a></li>";
        mainMenuHtml += "<li " + ((requestUrl.equals("/acl.html") ? "class=\"active\"" : "")) + "><a href=\"/acl.html\"><span class=\"glyphicon glyphicon-lock\"></span> Access Lists</a></li>";
        mainMenuHtml += "<li " + ((requestUrl.equals("/netflow.html") ? "class=\"active\"" : "")) + "><a href=\"/netflow.html\"><span class=\"glyphicon glyphicon-share-alt\"></span> Flow Export</a></li>";
        mainMenuHtml += "</ul>";
        String headerTemplate = this.getTemplate("/template/header.tpl.html");

        String title = "SwSwitch | ";
        switch (requestUrl) {
            case "/status.html": {
                title += "Switch Status";
                break;
            }
            case "/interface.html": {
                title += "Interfaces";
                break;
            }
            case "/acl.html": {
                title += "Access Lists";
                break;
            }

            case "/netflow.html": {
                title += "Flow Export";
                break;
            }
        }

        headerTemplate = headerTemplate.replaceAll("%site_title%", title);
        headerTemplate = headerTemplate.replaceAll("%main_menu_html%", mainMenuHtml);
        return headerTemplate;
    }

    private String getTemplate(String path) throws IOException, ServletException {
        String requestFileName = "/net/ctrdn/stuba/psip/swswitch/adminportal" + path;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is = getClass().getResourceAsStream(requestFileName);
        if (is == null) {
            throw new ServletException("Template not found " + requestFileName);
        }
        byte[] buffer = new byte[1024];
        while (is.available() > 0) {
            int rd = is.read(buffer, 0, buffer.length);
            baos.write(buffer, 0, rd);
        }
        return baos.toString("UTF-8");
    }
}
