package com.acme;

import java.sql.*;
import javax.servlet.http.*;
import javax.xml.parsers.DocumentBuilderFactory;

public class ReportDao {
    public ResultSet find(Connection c, HttpServletRequest request) throws Exception {
        Statement st = c.createStatement();
        return st.executeQuery("SELECT * FROM reports WHERE owner = '" + request.getParameter("owner") + "'");
    }
    public void export(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Runtime.getRuntime().exec("/opt/tools/export.sh " + request.getParameter("id"));
        response.sendRedirect(request.getParameter("returnUrl"));
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    }
}
