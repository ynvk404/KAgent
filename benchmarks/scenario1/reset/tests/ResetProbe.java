package org.kagent.scenario1.reset;

import java.io.*;
import java.sql.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.owasp.benchmark.helpers.DatabaseHelper;
import org.hibernate.Session;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Fixed mutations only, installed exclusively on disposable test targets. */
public final class ResetProbe extends HttpServlet {
    private static Connection unaccounted;
    private static List<Integer> hobbies(Session session) {
        boolean own=!session.getTransaction().isActive();
        if(own) session.beginTransaction();
        try {
            List<Integer> values=new ArrayList<>();
            for(Object value:session.createQuery("from User u order by u.userId").list())
                values.add(((org.owasp.benchmark.helpers.entities.User)value).getHobbyId());
            return values;
        } finally { if(own) session.getTransaction().rollback(); }
    }
    @Override protected void doGet(HttpServletRequest req,HttpServletResponse resp) throws IOException,ServletException {
        if(!"1".equals(System.getenv("KAGENT_RESET_TEST_PROBES"))) { resp.sendError(404);return; }
        Map<String,Object> result=new LinkedHashMap<>();
        try {
            String action=req.getParameter("action");
            if("committed".equals(action)) {
                for(String url:List.of(ResetLifecycle.SERVER,ResetLifecycle.EMBEDDED))
                    try(Connection c=CatalogBaseline.connect(url);Statement s=c.createStatement()) {
                        s.execute("UPDATE EMPLOYEE SET SALARY=777");
                        s.execute("INSERT INTO CERTIFICATE(CERTIFICATE_NAME,EMPLOYEE_ID) VALUES('changed',0)");
                    }
            } else if("ddl".equals(action)) {
                for(String url:List.of(ResetLifecycle.SERVER,ResetLifecycle.EMBEDDED))
                    try(Connection c=CatalogBaseline.connect(url);Statement s=c.createStatement()) {
                        s.execute("ALTER TABLE EMPLOYEE ADD COLUMN EXTRA VARCHAR(12)");
                        s.execute("CREATE TABLE EXTRA(ID INT PRIMARY KEY)");
                        s.execute("CREATE SCHEMA EXTRA AUTHORIZATION DBA");
                    }
                try(Connection c=CatalogBaseline.connect(ResetLifecycle.SERVER);Statement s=c.createStatement()) {
                    s.execute("DROP PROCEDURE VERIFYUSERPASSWORD");
                    s.execute("CREATE PROCEDURE EXTRA_PROC() MODIFIES SQL DATA BEGIN ATOMIC DELETE FROM USERS; END");
                }
            } else if("rolled-back".equals(action)) {
                for(String url:List.of(ResetLifecycle.SERVER,ResetLifecycle.EMBEDDED))
                    try(Connection c=CatalogBaseline.connect(url);Statement s=c.createStatement()) {
                        c.setAutoCommit(false);
                        s.execute("INSERT INTO EMPLOYEE(FIRST_NAME,LAST_NAME,SALARY) VALUES('temp','temp',999)");
                        c.rollback();
                    }
            } else if("hibernate-active".equals(action)) {
                Session session=DatabaseHelper.hibernateUtil.getSession();
                session.beginTransaction();
                session.createSQLQuery("UPDATE EMPLOYEE SET SALARY=888").executeUpdate();
            } else if("spring".equals(action)) {
                DatabaseHelper.JDBCtemplate.update("INSERT INTO USERS(USERNAME,PASSWORD) VALUES('changed','changed')");
            } else if("unaccounted".equals(action)) {
                unaccounted=CatalogBaseline.connect(ResetLifecycle.SERVER);unaccounted.setAutoCommit(false);
                unaccounted.createStatement().execute("INSERT INTO SCORE(NICK,SCORE) VALUES('unaccounted',999)");
            } else if("allocators".equals(action)) {
                Session session=DatabaseHelper.hibernateUtil.getSession();
                session.beginTransaction();
                org.owasp.benchmark.helpers.entities.User user=new org.owasp.benchmark.helpers.entities.User();
                user.setName("allocator");user.setPassword("fixture");user.setHobbyId(1);
                org.owasp.benchmark.helpers.entities.Hobby hobby=new org.owasp.benchmark.helpers.entities.Hobby();hobby.setName("allocator");
                result.put("user_id",session.save(user));result.put("hobby_id",session.save(hobby));
                session.getTransaction().rollback();
            } else if("delay".equals(action)) {
                Thread.sleep(Long.parseLong(req.getParameter("milliseconds")));
            } else if("session".equals(action)) {
                result.put("existing",req.getSession(false)!=null);
                result.put("session_hash",Integer.toHexString(req.getSession().getId().hashCode()));
            } else if(!"inspect".equals(action)) throw new IllegalArgumentException("unknown probe");
            result.put("jdbc",System.identityHashCode(DatabaseHelper.getSqlConnection()));
            result.put("spring",System.identityHashCode(DatabaseHelper.JDBCtemplate.getDataSource()));
            result.put("normal_factory",System.identityHashCode(DatabaseHelper.hibernateUtil.getSessionFactory()));
            result.put("classic_factory",System.identityHashCode(DatabaseHelper.hibernateUtilClassic.getSessionFactory()));
            if(!"hibernate-active".equals(action) && !"unaccounted".equals(action)) {
                result.put("normal_hobbies",hobbies(DatabaseHelper.hibernateUtil.getSession()));
                result.put("classic_hobbies",hobbies(DatabaseHelper.hibernateUtilClassic.getClassicSession()));
            }
            result.put("ok",true);
            resp.setContentType("application/json");new ObjectMapper().writeValue(resp.getOutputStream(),result);
        } catch(Exception e) { throw new ServletException("fixed reset probe failed",e); }
    }
}
