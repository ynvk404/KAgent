package org.kagent.scenario1.reset;

import java.io.*;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import javax.servlet.*;
import javax.servlet.http.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

/** Exercise the production filter/control code; only the SQL/lifecycle adapter is a test double. */
public final class ResetGateIdleTest {
    static final ObjectMapper json=new ObjectMapper();
    static final String CASE="/sqli-01/BenchmarkTest00018";
    static ResetGate gate=new ResetGate();
    interface Call { Object invoke(String name,Object[] args) throws Throwable; }
    @SuppressWarnings("unchecked") static <T> T proxy(Class<T> type,Call call) {
        return (T)Proxy.newProxyInstance(type.getClassLoader(),new Class<?>[]{type},(p,m,a)->{
            Object value=call.invoke(m.getName(),a);
            if(value!=null || !m.getReturnType().isPrimitive()) return value;
            if(m.getReturnType()==boolean.class) return false;
            if(m.getReturnType()==int.class) return 0;
            if(m.getReturnType()==long.class) return 0L;
            return null;
        });
    }
    static ServletInputStream input(byte[] bytes) {
        ByteArrayInputStream in=new ByteArrayInputStream(bytes);
        return new ServletInputStream() {
            public int read() { return in.read(); }
            public boolean isFinished() { return in.available()==0; }
            public boolean isReady() { return true; }
            public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
        };
    }
    static final class Reply {
        int status=200; ByteArrayOutputStream body=new ByteArrayOutputStream();
        HttpServletResponse response=proxy(HttpServletResponse.class,(name,args)->{
            if(name.equals("sendError") || name.equals("setStatus")) status=(Integer)args[0];
            if(name.equals("getOutputStream")) return new ServletOutputStream() {
                public void write(int b) { body.write(b); }
                public boolean isReady() { return true; }
                public void setWriteListener(WriteListener listener) { throw new UnsupportedOperationException(); }
            };
            return null;
        });
        Map<?,?> data() throws Exception { return json.readValue(body.toByteArray(),Map.class); }
    }
    static Reply send(String path,String method,Map<String,String> headers,byte[] body,FilterChain chain) throws Exception {
        HttpServletRequest request=proxy(HttpServletRequest.class,(name,args)->switch(name) {
            case "getRequestURI" -> "/benchmark"+path;
            case "getContextPath" -> "/benchmark";
            case "getMethod" -> method;
            case "getHeader" -> headers.get((String)args[0]);
            case "getInputStream" -> input(body);
            default -> null;
        });
        Reply result=new Reply();gate.doFilter(request,result.response,chain);return result;
    }
    static Reply request(String path) throws Exception {
        return send(path,"GET",Map.of(),new byte[0],(req,resp)->resp.getOutputStream().write("normal access".getBytes(StandardCharsets.UTF_8)));
    }
    static Reply control(String action) throws Exception {
        Map<String,Object> data=new HashMap<>(Map.of("action",action,"nonce","1".repeat(32)));
        if(action.equals("authorize")) { data.put("route",CASE);data.put("lease_seconds",1); }
        return send("/__kagent_reset","POST",Map.of("X-KAgent-Reset-Token",System.getenv("KAGENT_RESET_TOKEN")),
            json.writeValueAsBytes(data),(req,resp)->{throw new AssertionError("control reached application");});
    }
    static void check(boolean value,String reason) { if(!value) throw new AssertionError(reason); }
    static void init() throws Exception {
        ServletContext context=proxy(ServletContext.class,(name,args)->switch(name) {
            case "getServerInfo" -> "Apache Tomcat/9.0.122";
            case "getClassLoader" -> ResetGate.class.getClassLoader();
            default -> null;
        });
        gate.init(proxy(FilterConfig.class,(name,args)->name.equals("getServletContext")?context:null));
    }
    static void serve() throws Exception {
        HttpServer server=HttpServer.create(new java.net.InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/benchmark",exchange->{
            try {
                String path=exchange.getRequestURI().getPath().substring("/benchmark".length());
                Map<String,String> headers=new HashMap<>();
                headers.put("X-KAgent-Reset-Token",exchange.getRequestHeaders().getFirst("X-KAgent-Reset-Token"));
                Reply reply=send(path,exchange.getRequestMethod(),headers,exchange.getRequestBody().readAllBytes(),
                    (req,resp)->resp.getOutputStream().write("normal access".getBytes(StandardCharsets.UTF_8)));
                byte[] bytes=reply.body.toByteArray();exchange.sendResponseHeaders(reply.status,bytes.length);
                exchange.getResponseBody().write(bytes);
            } catch(Exception error) { exchange.sendResponseHeaders(500,-1); }
            finally { exchange.close(); }
        });
        server.start();System.out.println(server.getAddress().getPort());System.out.flush();
        System.in.read();server.stop(0);
    }
    public static void main(String[] args) throws Exception {
        init();String mode=args[0];
        try {
            if(mode.equals("http")) { serve();return; }
            if(mode.equals("idle")) {
                check(request("/").status==200,"browser idle");
                check(send(CASE,"POST",Map.of("User-Agent","KAgent"),new byte[0],(req,resp)->{}).status==200,"TUI idle");
                check(send("/__kagent_reset","POST",Map.of(),new byte[0],(req,resp)->{}).status==403,"control still private");
            } else if(mode.equals("transition")) {
                CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
                ExecutorService threads=Executors.newFixedThreadPool(2);
                try {
                    Future<Reply> active=threads.submit(()->send("/","GET",Map.of(),new byte[0],(req,resp)->{
                        entered.countDown();try { release.await();ResetLifecycle.dirty=true; }
                        catch(InterruptedException e) { Thread.currentThread().interrupt();throw new ServletException(e); }
                    }));
                    check(entered.await(2,TimeUnit.SECONDS),"request entered");
                    check(control("block").status==200,"block");check(request("/").status==503,"new requests blocked");
                    CountDownLatch resetting=new CountDownLatch(1);
                    Future<Reply> reset=threads.submit(()->{resetting.countDown();return control("reset");});
                    check(resetting.await(2,TimeUnit.SECONDS),"reset started");
                    try { reset.get(150,TimeUnit.MILLISECONDS);throw new AssertionError("reset did not drain"); }
                    catch(TimeoutException expected) { check(ResetLifecycle.restores==0,"restore before drain"); }
                    release.countDown();check(active.get().status==200,"active request finished");
                    Reply clean=reset.get(2,TimeUnit.SECONDS);check(clean.status==200,"verified reset");
                    check(control("authorize").status==200 && request(CASE).status==200,"case admission");
                    check(request("/").status==503 && request("/sqli-01/BenchmarkTest00019").status==503,"case restriction");
                    Reply after=control("reset");
                    check(after.status==200 && after.data().get("boot_id").equals(clean.data().get("boot_id")),"same boot");
                    check(((Number)after.data().get("generation")).intValue()==2,"logical generations");
                    check(control("idle").status==200 && request("/").status==200,"verified return to idle");
                } finally { release.countDown();threads.shutdownNow(); }
            } else if(mode.equals("session")) {
                boolean[] invalidated={false};HttpSession[] session=new HttpSession[1];
                session[0]=proxy(HttpSession.class,(name,values)->{
                    if(name.equals("invalidate")) { invalidated[0]=true;gate.sessionDestroyed(new HttpSessionEvent(session[0])); }
                    if(name.equals("hashCode")) return 123;
                    if(name.equals("equals")) return session[0]==values[0];
                    return null;
                });
                gate.sessionCreated(new HttpSessionEvent(session[0]));control("block");
                check(control("reset").status==200 && invalidated[0],"idle sessions invalidated");
                check(control("idle").status==200,"idle after session cleanup");
            } else if(mode.equals("reset-failure")) {
                control("block");ResetLifecycle.failRestore=true;
                check(control("reset").status==503,"reset failure");
                check(control("idle").status==503 && request("/").status==503,"permanent fail closed");
            } else if(mode.equals("drain-timeout")) {
                CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
                ExecutorService threads=Executors.newSingleThreadExecutor();
                try {
                    Future<Reply> running=threads.submit(()->send("/","GET",Map.of(),new byte[0],(req,resp)->{
                        entered.countDown();try { release.await(); }
                        catch(InterruptedException e) { throw new ServletException(e); }
                    }));
                    check(entered.await(2,TimeUnit.SECONDS),"request entered");
                    check(control("reset").status==503 && ResetLifecycle.restores==0,"failed drain did not restore");
                    check(request("/").status==503 && control("idle").status==503,"drain failure closed");
                    release.countDown();running.get(2,TimeUnit.SECONDS);
                } finally { release.countDown();threads.shutdownNow(); }
            } else if(mode.equals("idle-failure")) {
                control("reset");ResetLifecycle.dirty=true;
                check(control("idle").status==503 && request("/").status==503,"idle verify failure closed");
            } else if(mode.equals("premature")) {
                control("block");check(control("authorize").status==503,"no admission before reset");
                check(request("/").status==503,"closed after rejected transition");
            } else if(mode.equals("crash")) {
                control("reset");control("authorize");Thread.sleep(1200);
                check(request(CASE).status==503 && request("/").status==503,"expired lease never restores idle");
            } else throw new IllegalArgumentException(mode);
            System.out.println("PASS "+mode);
        } finally { gate.destroy(); }
    }
}

final class ResetLifecycle {
    static volatile boolean dirty=false,failRestore=false;static volatile int restores=0;
    void capture() { dirty=false; }
    void restore() throws Exception {
        if(failRestore) throw new IllegalStateException("fixed reset failure");
        dirty=false;restores++;verify();
    }
    void verify() { if(dirty) throw new IllegalStateException("baseline mismatch"); }
    Map<String,String> hashes() { return Map.of("server","a".repeat(64),"embedded","b".repeat(64)); }
}
final class InstallProbe { static void assertInstalled(ServletContext context) {} }
