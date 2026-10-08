package org.kagent.scenario1.reset;

import java.sql.*;
import java.util.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/** Immutable SQL baseline; no catalog files or HSQLDB internals are used. */
public final class CatalogBaseline {
    public final String url;
    private final List<String> ddl;
    private final Map<String,List<List<Object>>> rows;
    private final Map<String,String> primaryKeys;
    private final Map<String,String> notNulls;
    private final String fingerprint;
    private final Map<String,String> components;
    private static final String[] METADATA = {
        "TABLES", "COLUMNS", "TABLE_CONSTRAINTS", "CHECK_CONSTRAINTS",
        "KEY_COLUMN_USAGE", "REFERENTIAL_CONSTRAINTS", "ROUTINES", "PARAMETERS",
        "SEQUENCES", "SCHEMATA", "AUTHORIZATIONS", "ROLE_AUTHORIZATION_DESCRIPTORS",
        "SYSTEM_PRIMARYKEYS", "SYSTEM_INDEXINFO", "SYSTEM_USERS"
    };

    private CatalogBaseline(String url, Connection c, Map<String,Integer> counts) throws Exception {
        this.url=url;
        if (!c.getMetaData().getDatabaseProductVersion().startsWith("2.7.4"))
            throw new IllegalStateException("HSQLDB identity mismatch");
        ddl=List.copyOf(script(c));
        rows=new TreeMap<>(); primaryKeys=new HashMap<>(); notNulls=new HashMap<>();
        Set<String> tables=tables(c);
        if (!tables.equals(counts.keySet())) throw new IllegalStateException("unexpected baseline tables");
        for (String table: tables) {
            List<List<Object>> data=read(c,"SELECT * FROM PUBLIC."+quote(table),false);
            if (data.size()!=counts.get(table)) throw new IllegalStateException("baseline seed inventory mismatch");
            rows.put(table,List.copyOf(data));
            try(ResultSet r=c.getMetaData().getPrimaryKeys(null,"PUBLIC",table)) {
                while(r.next()) {
                    String key=r.getString("PK_NAME");
                    if(primaryKeys.putIfAbsent(table,key)!=null && !primaryKeys.get(table).equals(key))
                        throw new IllegalStateException("multiple primary keys");
                }
            }
        }
        try(Statement s=c.createStatement();ResultSet r=s.executeQuery(
            "SELECT T.TABLE_NAME,C.CONSTRAINT_NAME,C.CHECK_CLAUSE FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS T "
            +"JOIN INFORMATION_SCHEMA.CHECK_CONSTRAINTS C ON T.CONSTRAINT_NAME=C.CONSTRAINT_NAME "
            +"AND T.CONSTRAINT_SCHEMA=C.CONSTRAINT_SCHEMA WHERE T.TABLE_SCHEMA='PUBLIC'")) {
            while(r.next()) {
                String clause=r.getString(3).replace("\"","").replace("(","").replace(")","").trim();
                clause=clause.substring(clause.lastIndexOf('.')+1);
                if(!clause.matches("[A-Z_]+ IS NOT NULL")) throw new IllegalStateException("unsupported baseline check: "+clause);
                notNulls.put(r.getString(1)+"."+clause.split(" ")[0],r.getString(2));
            }
        }
        fingerprint=fingerprint(c);
        components=components(c);
        validateSeeds(c,counts.containsKey("USERS"));
        validateMetadata(c,counts.containsKey("USERS"));
    }

    public static CatalogBaseline capture(String url, Map<String,Integer> counts) throws Exception {
        try(Connection c=connect(url)) { return new CatalogBaseline(url,c,counts); }
    }
    public static Connection connect(String url) throws SQLException {
        return DriverManager.getConnection(url,"sa","");
    }
    public String hash() { return fingerprint; }
    private static String quote(String v) { return "\""+v.replace("\"","\"\"")+"\""; }
    private static Set<String> tables(Connection c) throws Exception {
        Set<String> out=new TreeSet<>();
        try(Statement s=c.createStatement();ResultSet r=s.executeQuery(
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='PUBLIC' AND TABLE_TYPE='BASE TABLE'")) {
            while(r.next()) out.add(r.getString(1));
        }
        return out;
    }
    private static List<List<Object>> read(Connection c,String sql,boolean sorted) throws Exception {
        List<List<Object>> out=new ArrayList<>();
        try(Statement s=c.createStatement()) {
            s.setQueryTimeout(15);
            try(ResultSet r=s.executeQuery(sql)) {
                while(r.next()) {
                    List<Object> row=new ArrayList<>();
                    for(int i=1;i<=r.getMetaData().getColumnCount();i++) {
                        Object value=r.getObject(i);
                        if(value instanceof byte[]) value=Base64.getEncoder().encodeToString((byte[])value);
                        row.add(value);
                    }
                    out.add(Collections.unmodifiableList(row));
                }
            }
        }
        if(sorted) out.sort(Comparator.comparing(CatalogBaseline::encode));
        return out;
    }
    private static String encode(List<Object> row) {
        StringBuilder out=new StringBuilder();
        for(Object v:row) {
            String str=v==null?"":v.getClass().getName()+":"+v;
            out.append(v==null?"N":Integer.toString(str.length())).append(':').append(str).append(';');
        }
        return out.toString();
    }
    private static List<String> script(Connection c) throws Exception {
        List<String> out=new ArrayList<>();
        try(Statement s=c.createStatement();ResultSet r=s.executeQuery("SCRIPT")) {
            while(r.next()) out.add(r.getString(1));
        }
        return out;
    }
    private static void validateSeeds(Connection c,boolean server) throws Exception {
        // Independent seed oracle, in addition to the captured complete-state comparison.
        String sql=server?"SELECT USERNAME,PASSWORD FROM PUBLIC.USERS ORDER BY USERID":
            "SELECT NAME,PASSWORD,HOBBYID FROM PUBLIC.USER ORDER BY USERID";
        List<List<Object>> expected=server?
            List.of(List.of("User01","P455w0rd"),List.of("User02","B3nchM3rk"),List.of("User03","a$c11"),List.of("foo","bar")):
            List.of(List.of("User1","P455w0rd",1),List.of("bar","P455w0rd",1),List.of("User3","P455w0rd",1));
        if(!read(c,sql,false).equals(expected)) throw new IllegalStateException("fresh seed oracle mismatch");
        if(server) {
            if(!read(c,"SELECT NICK,SCORE FROM PUBLIC.SCORE ORDER BY USERID",false).equals(
                List.of(List.of("User03",155),List.of("foo",40)))) throw new IllegalStateException("score seed mismatch");
            if(!read(c,"SELECT FIRST_NAME,LAST_NAME,SALARY FROM PUBLIC.EMPLOYEE",false).equals(
                List.of(List.of("foo","bar",34567)))) throw new IllegalStateException("employee seed mismatch");
        } else {
            if(!read(c,"SELECT NAME FROM PUBLIC.HOBBY",false).equals(List.of(List.of("Walk"))))
                throw new IllegalStateException("hobby seed mismatch");
            if(!read(c,"SELECT FIRST_NAME,LAST_NAME,SALARY FROM PUBLIC.EMPLOYEE",false).equals(
                List.of(List.of("Name","lname",100)))) throw new IllegalStateException("employee seed mismatch");
            List<List<Object>> cert=read(c,"SELECT CERTIFICATE_NAME FROM PUBLIC.CERTIFICATE",true);
            List<List<Object>> wanted=new ArrayList<>(List.of(List.of("MCA"),List.of("MBA"),List.of("bar")));
            wanted.sort(Comparator.comparing(CatalogBaseline::encode));
            if(!cert.equals(wanted)) throw new IllegalStateException("certificate seed mismatch");
        }
    }
    private static void validateMetadata(Connection c,boolean server) throws Exception {
        Map<String,String> oracle=new TreeMap<>();
        oracle.put("EMPLOYEE","ID:4:0:YES:null,FIRST_NAME:12:1:NO:NULL,LAST_NAME:12:1:NO:NULL,SALARY:4:1:NO:NULL");
        oracle.put("CERTIFICATE","ID:4:0:YES:null,CERTIFICATE_NAME:12:1:NO:NULL,EMPLOYEE_ID:4:1:NO:NULL");
        if(server) {
            oracle.put("USERS","USERID:4:0:YES:null,USERNAME:12:1:NO:null,PASSWORD:12:1:NO:null");
            oracle.put("SCORE","USERID:4:0:YES:null,NICK:12:1:NO:null,SCORE:4:1:NO:null");
        } else {
            oracle.put("USER","USERID:4:0:NO:null,NAME:12:1:NO:null,PASSWORD:12:1:NO:null,HOBBYID:4:1:NO:null");
            oracle.put("HOBBY","HOBBYID:4:0:NO:null,NAME:12:1:NO:null");
        }
        for(var entry:oracle.entrySet()) {
            List<String> actual=new ArrayList<>();
            try(ResultSet r=c.getMetaData().getColumns(null,"PUBLIC",entry.getKey(),null)) {
                while(r.next()) {
                    String name=r.getString("COLUMN_NAME");int type=r.getInt("DATA_TYPE");
                    actual.add(name+":"+type+":"+r.getInt("NULLABLE")+":"+r.getString("IS_AUTOINCREMENT")+":"+r.getString("COLUMN_DEF"));
                    if(type==Types.VARCHAR) {
                        int length=r.getInt("COLUMN_SIZE");
                        int expected=name.equals("CERTIFICATE_NAME")?30:
                            Set.of("FIRST_NAME","LAST_NAME").contains(name)?20:50;
                        if(length!=expected) throw new IllegalStateException("independent column size mismatch");
                    }
                }
            }
            if(!String.join(",",actual).equals(entry.getValue())) throw new IllegalStateException("independent column metadata mismatch: "+entry.getKey());
            List<List<Object>> keys=read(c,"SELECT CONSTRAINT_TYPE FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA='PUBLIC' AND TABLE_NAME='"+entry.getKey()+"' AND CONSTRAINT_TYPE IN ('PRIMARY KEY','FOREIGN KEY','UNIQUE')",true);
            if(!keys.equals(List.of(List.of("PRIMARY KEY")))) throw new IllegalStateException("independent key metadata mismatch");
        }
        Set<String> routines=new TreeSet<>();
        for(List<Object> row:read(c,"SELECT ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA='PUBLIC'",false)) routines.add((String)row.get(0));
        if(!routines.equals(server?Set.of("VERIFYUSERPASSWORD","VERIFYEMPLOYEESALARY"):Set.of()))
            throw new IllegalStateException("independent procedure inventory mismatch");
    }
    private static String fingerprint(Connection c) throws Exception {
        MessageDigest sha=MessageDigest.getInstance("SHA-256");
        // SCRIPT covers database configuration, routines, DDL, grants and next identities.
        for(String line:script(c)) sha.update((line+"\n").getBytes(StandardCharsets.UTF_8));
        for(String table:METADATA) {
            sha.update(table.getBytes(StandardCharsets.UTF_8));
            for(List<Object> row:read(c,"SELECT * FROM INFORMATION_SCHEMA."+table,true))
                sha.update((encode(row)+"\n").getBytes(StandardCharsets.UTF_8));
        }
        for(String table:tables(c)) {
            sha.update(table.getBytes(StandardCharsets.UTF_8));
            for(List<Object> row:read(c,"SELECT * FROM PUBLIC."+quote(table),true))
                sha.update((encode(row)+"\n").getBytes(StandardCharsets.UTF_8));
        }
        return HexFormat.of().formatHex(sha.digest());
    }
    public void verify() throws Exception {
        try(Connection c=connect(url)) {
            String actual=fingerprint(c);
            if(!fingerprint.equals(actual)) {
                Map<String,String> current=components(c);
                List<String> changed=new ArrayList<>();
                for(String key:components.keySet()) if(!components.get(key).equals(current.get(key))) changed.add(key);
                throw new IllegalStateException("catalog full-state mismatch: "+actual+" components="+changed);
            }
        }
    }
    private static Map<String,String> components(Connection c) throws Exception {
        Map<String,String> result=new TreeMap<>();
        Map<String,StringBuilder> scriptGroups=new TreeMap<>();
        for(String line:script(c)) {
            String[] tokens=line.split(" ");
            String prefix=tokens[0]+" "+tokens[1];
            scriptGroups.computeIfAbsent("SCRIPT/"+prefix,k->new StringBuilder()).append(line).append('\n');
        }
        for(var entry:scriptGroups.entrySet()) result.put(entry.getKey(),hash(entry.getValue().toString()));
        for(String table:METADATA) result.put("METADATA/"+table,hash(read(c,"SELECT * FROM INFORMATION_SCHEMA."+table,true).toString()));
        for(String table:tables(c)) result.put("ROWS/"+table,hash(read(c,"SELECT * FROM PUBLIC."+quote(table),true).toString()));
        return Map.copyOf(result);
    }
    private static String hash(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }
    private String namedTable(String sql) {
        String table=sql.substring(sql.indexOf("PUBLIC.")+7,sql.indexOf('('));
        String body=sql.substring(sql.indexOf('(')+1,sql.length()-1);
        String[] columns=body.split(",(?=[A-Z_]+ (?:INTEGER|VARCHAR))");
        List<String> parts=new ArrayList<>(); String pkColumn=null;
        for(String col:columns) {
            String name=col.split(" ")[0];
            if(col.contains(" PRIMARY KEY")) { pkColumn=name; col=col.replace(" PRIMARY KEY",""); }
            String nn=notNulls.get(table+"."+name);
            if(col.contains(" NOT NULL")) col=col.replace(" NOT NULL",nn==null?"":" CONSTRAINT "+quote(nn)+" NOT NULL");
            parts.add(col);
        }
        if(pkColumn==null || !primaryKeys.containsKey(table)) throw new IllegalStateException("unsupported baseline primary key");
        parts.add("CONSTRAINT "+quote(primaryKeys.get(table))+" PRIMARY KEY("+pkColumn+")");
        return sql.substring(0,sql.indexOf('(')+1)+String.join(",",parts)+")";
    }
    public void restore() throws Exception {
        try(Connection c=connect(url);Statement s=c.createStatement()) {
            s.setQueryTimeout(15);
            Set<String> unchanged=new HashSet<>(script(c));
            // Disallow transactions not owned by this helper. Known application handles were closed first.
            try(ResultSet r=s.executeQuery("SELECT * FROM INFORMATION_SCHEMA.SYSTEM_SESSIONS WHERE SESSION_ID<>SESSION_ID()")) {
                if(r.next()) throw new IllegalStateException("unaccounted connection or transaction");
            }
            List<String> schemas=new ArrayList<>();
            try(ResultSet r=s.executeQuery("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA','SYSTEM_LOBS','PUBLIC','DEFINITION_SCHEMA','SQLJ')")) {
                while(r.next()) schemas.add(r.getString(1));
            }
            for(String schema:schemas) s.execute("DROP SCHEMA "+quote(schema)+" CASCADE");
            s.execute("DROP SCHEMA PUBLIC CASCADE");
            List<String> users=new ArrayList<>();
            try(ResultSet r=s.executeQuery("SELECT USER_NAME FROM INFORMATION_SCHEMA.SYSTEM_USERS WHERE USER_NAME<>'SA'")) {
                while(r.next()) users.add(r.getString(1));
            }
            for(String user:users) s.execute("DROP USER "+quote(user));
            for(String sql:ddl) {
                if(sql.startsWith("CREATE USER SA ")) continue;
                // Reapplying unchanged settings can alter HSQLDB's emitted
                // collation spelling. Retain the original object when equal;
                // changed settings are restored and still compared exactly.
                if((sql.startsWith("SET DATABASE ") || sql.startsWith("SET FILES ")) && unchanged.contains(sql)) continue;
                // DROP of the default schema recreates PUBLIC automatically in 2.7.4.
                if(sql.equals("CREATE SCHEMA PUBLIC AUTHORIZATION DBA")) continue;
                if(sql.startsWith("CREATE MEMORY TABLE PUBLIC.")) sql=namedTable(sql);
                s.execute(sql);
            }
            for(var entry:rows.entrySet()) {
                if(entry.getValue().isEmpty()) continue;
                int n=entry.getValue().get(0).size();
                try(PreparedStatement p=c.prepareStatement("INSERT INTO PUBLIC."+quote(entry.getKey())+" VALUES("+String.join(",",Collections.nCopies(n,"?"))+")")) {
                    for(List<Object> row:entry.getValue()) {
                        for(int i=0;i<n;i++) p.setObject(i+1,row.get(i));
                        p.executeUpdate();
                    }
                }
            }
            // Explicit identity positions are part of the immutable SCRIPT, including empty tables.
            for(String sql:ddl) if(sql.startsWith("ALTER TABLE ") || sql.startsWith("ALTER SEQUENCE ")) s.execute(sql);
        }
    }
}
