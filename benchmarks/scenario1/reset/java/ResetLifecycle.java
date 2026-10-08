package org.kagent.scenario1.reset;

import java.lang.reflect.*;
import java.util.*;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import java.sql.Connection;
import org.hibernate.Session;
import org.owasp.benchmark.helpers.DatabaseHelper;
import org.owasp.benchmark.helpers.HibernateUtil;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/** Version-pinned adapter for the original helpers; never reruns seed initializers. */
final class ResetLifecycle {
    static final String SERVER="jdbc:hsqldb:hsql://localhost/benchmarkDataBase";
    static final String EMBEDDED="jdbc:hsqldb:benchmarkDataBase;sql.enforce_size=false";
    private CatalogBaseline server,embedded;
    private DataSource jndi;
    private Map<String,Object> springConfig;
    private ClassPathXmlApplicationContext springContext;

    static Object field(Object obj,String name) throws Exception {
        Class<?> cls=obj instanceof Class<?>?(Class<?>)obj:obj.getClass();
        Field f=cls.getDeclaredField(name); f.setAccessible(true);
        return f.get(obj instanceof Class<?>?null:obj);
    }
    static void set(Object obj,String name,Object val) throws Exception {
        Class<?> cls=obj instanceof Class<?>?(Class<?>)obj:obj.getClass();
        Field f=cls.getDeclaredField(name); f.setAccessible(true); f.set(obj instanceof Class<?>?null:obj,val);
    }
    static void invoke(Object obj,String method) throws Exception { obj.getClass().getMethod(method).invoke(obj); }
    private static Map<String,Object> poolConfig(DataSource data) throws Exception {
        Map<String,Object> result=new TreeMap<>();
        for(String key:List.of("DriverClassName","Url","Username","Password","DefaultAutoCommit","DefaultReadOnly",
            "DefaultTransactionIsolation","InitialSize","MaxActive","MaxIdle","MinIdle","MaxWait","TestOnBorrow",
            "TestOnReturn","TestWhileIdle","ValidationQuery","TimeBetweenEvictionRunsMillis","NumTestsPerEvictionRun")) {
            result.put(key,data.getClass().getMethod("get"+key).invoke(data));
        }
        return result;
    }
    void capture() throws Exception {
        Class.forName(DatabaseHelper.class.getName());
        jndi=(DataSource)new InitialContext().lookup("java:comp/env/jdbc/BenchmarkDB");
        springConfig=Collections.unmodifiableMap(poolConfig(DatabaseHelper.JDBCtemplate.getDataSource()));
        server=CatalogBaseline.capture(SERVER,Map.of("USERS",4,"SCORE",2,"EMPLOYEE",1,"CERTIFICATE",0));
        embedded=CatalogBaseline.capture(EMBEDDED,Map.of("USER",3,"HOBBY",1,"EMPLOYEE",1,"CERTIFICATE",3));
        verify();
    }
    Map<String,String> hashes() { return Map.of("server",server.hash(),"embedded",embedded.hash()); }
    private void closeHibernate(HibernateUtil util,boolean classic) throws Exception {
        Session session=classic?util.getClassicSession():util.getSession();
        if(session.getTransaction().isActive()) session.getTransaction().rollback();
        session.clear(); session.close();
        Connection c=(Connection)field(util,"conn");
        if(c!=null && !c.isClosed()) { if(!c.getAutoCommit()) c.rollback(); c.close(); }
        util.getSessionFactory().close();
    }
    void restore() throws Exception {
        Connection connection=(Connection)field(DatabaseHelper.class,"conn");
        if(connection!=null && !connection.isClosed()) { connection.rollback(); connection.close(); }
        set(DatabaseHelper.class,"conn",null);
        closeHibernate(DatabaseHelper.hibernateUtil,false);
        closeHibernate(DatabaseHelper.hibernateUtilClassic,true);
        invoke(DatabaseHelper.JDBCtemplate.getDataSource(),"close");
        if(springContext!=null) { springContext.close(); springContext=null; }
        invoke(jndi,"close");
        server.restore(); embedded.restore();
        // Tomcat DBCP2's datasource object remains bound in JNDI; start replaces its closed pool.
        // Its first borrow matches the original static JDBC startup lifecycle.
        invoke(jndi,"start");
        if(DatabaseHelper.getSqlConnection()==null || DatabaseHelper.getSqlConnection().isClosed())
            throw new IllegalStateException("static JDBC reconnect failed");
        DatabaseHelper.hibernateUtil=new HibernateUtil(false);
        DatabaseHelper.hibernateUtilClassic=new HibernateUtil(true);
        springContext=new ClassPathXmlApplicationContext("/context.xml",DatabaseHelper.class);
        DataSource data=(DataSource)springContext.getBean("dataSource");
        DatabaseHelper.JDBCtemplate=new org.springframework.jdbc.core.JdbcTemplate(data);
        // Do not borrow a Spring connection here: DBCP 1.4 changes testOnBorrow on first borrow.
        verify();
    }
    void verify() throws Exception {
        server.verify(); embedded.verify();
        if(!springConfig.equals(poolConfig(DatabaseHelper.JDBCtemplate.getDataSource())))
            throw new IllegalStateException("Spring pool startup configuration mismatch");
        Connection c=DatabaseHelper.getSqlConnection();
        if(c==null || c.isClosed() || c.getAutoCommit()) throw new IllegalStateException("JDBC lifecycle mismatch");
        for(HibernateUtil util:List.of(DatabaseHelper.hibernateUtil,DatabaseHelper.hibernateUtilClassic))
            if(util.getSessionFactory().isClosed()) throw new IllegalStateException("Hibernate factory closed");
        if(!DatabaseHelper.hibernateUtil.getSession().isOpen() || !DatabaseHelper.hibernateUtilClassic.getClassicSession().isOpen())
            throw new IllegalStateException("Hibernate session closed");
    }
}
