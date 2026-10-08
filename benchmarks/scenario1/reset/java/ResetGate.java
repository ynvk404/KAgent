package org.kagent.scenario1.reset;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import javax.servlet.*;
import javax.servlet.http.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Control traffic terminates before the original filters. Requests are closed by default. */
public final class ResetGate implements Filter, HttpSessionListener {
    public static final String COMMIT="8b67a88d73b2594570fc21150705283de884620b";
    private static final Object monitor=new Object();
    private static final Set<HttpSession> sessions=ConcurrentHashMap.newKeySet();
    private static final ObjectMapper json=new ObjectMapper();
    private static final ResetLifecycle lifecycle=new ResetLifecycle();
    private static volatile String state="CLOSED",route=null;
    private static volatile long deadline=0,generation=0;
    private static int active=0;
    private static String token;
    private static ServletContext servletContext;
    private static volatile boolean initialized=false;
    private static final String boot=UUID.randomUUID().toString();
    private final ExecutorService executor=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"kagent-logical-reset");t.setDaemon(true);return t;});

    @Override public void init(FilterConfig config) throws ServletException {
        servletContext=config.getServletContext();
        token=System.getenv("KAGENT_RESET_TOKEN");
        try {
            if(token==null || token.length()<32) throw new IllegalStateException("reset credential missing");
            if(!System.getProperty("java.specification.version").equals("17")) throw new IllegalStateException("JDK mismatch");
            if(!config.getServletContext().getServerInfo().equals("Apache Tomcat/9.0.122")) throw new IllegalStateException("Tomcat mismatch");
            if(!config.getServletContext().getClassLoader().equals(getClass().getClassLoader())) throw new IllegalStateException("application classloader mismatch");
            lifecycle.capture(); initialized=true;
        } catch(Exception e) { state="FAILED"; throw new ServletException("baseline capture failed",e); }
    }
    @Override public void sessionCreated(HttpSessionEvent e) { sessions.add(e.getSession()); }
    @Override public void sessionDestroyed(HttpSessionEvent e) { sessions.remove(e.getSession()); }
    private static void closeGate() { synchronized(monitor) { state="CLOSED";route=null;deadline=0;monitor.notifyAll(); } }
    private static void reset(long drainMillis) throws Exception {
        closeGate();
        long until=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(drainMillis);
        synchronized(monitor) {
            while(active>0) {
                long remaining=until-System.nanoTime();
                if(remaining<=0) throw new TimeoutException("active request drain timeout");
                TimeUnit.NANOSECONDS.timedWait(monitor,remaining);
            }
        }
        for(HttpSession session:List.copyOf(sessions)) {
            try { session.invalidate(); } catch(IllegalStateException alreadyInvalid) { sessions.remove(session); }
        }
        if(!sessions.isEmpty()) throw new IllegalStateException("session invalidation incomplete");
        lifecycle.restore(); generation++;
    }
    private Map<String,Object> evidence(String nonce,long started) {
        Map<String,Object> result=new LinkedHashMap<>();
        result.put("protocol","kagent-logical-reset-v1");result.put("nonce",nonce);result.put("state",state);
        result.put("boot_id",boot);result.put("generation",generation);
        result.put("source_commit",COMMIT);result.put("hsqldb","2.7.4");result.put("tomcat","9.0.122");result.put("jdk","17");
        result.put("war_sha256",System.getenv("KAGENT_BASE_WAR_SHA256"));
        result.put("reset_source_sha256",System.getenv("KAGENT_RESET_SOURCE_SHA256"));
        result.put("catalogs",initialized?lifecycle.hashes():Map.of());
        result.put("verified",initialized && !state.equals("FAILED"));
        result.put("active_requests",active);result.put("tracked_sessions",sessions.size());
        result.put("internal_seconds",(System.nanoTime()-started)/1e9);
        result.put("orm_cache_parity",false);
        return result;
    }
    @Override public void doFilter(ServletRequest req,ServletResponse resp,FilterChain chain) throws IOException,ServletException {
        HttpServletRequest request=(HttpServletRequest)req; HttpServletResponse response=(HttpServletResponse)resp;
        String path=request.getRequestURI().substring(request.getContextPath().length());
        if(path.equals("/__kagent_reset")) { control(request,response); return; }
        synchronized(monitor) {
            if(!state.equals("OPEN") || System.nanoTime()>deadline || !path.equals(route)) {
                response.sendError(503,"testcase admission closed");return;
            }
            active++;
        }
        try {
            if(request.isAsyncSupported()) throw new ServletException("unexpected async dispatch support");
            chain.doFilter(req,resp);
        } finally { synchronized(monitor) { active--;monitor.notifyAll(); } }
    }
    private synchronized void control(HttpServletRequest req,HttpServletResponse resp) throws IOException {
        String supplied=req.getHeader("X-KAgent-Reset-Token");
        if(!req.getMethod().equals("POST") || supplied==null || token==null || !MessageDigest.isEqual(
            token.getBytes(StandardCharsets.UTF_8),supplied.getBytes(StandardCharsets.UTF_8))) { resp.sendError(403);return; }
        long started=System.nanoTime(); String nonce="";
        try {
            byte[] body=req.getInputStream().readNBytes(4097);
            if(body.length>4096) throw new IllegalArgumentException("oversized control request");
            Map<?,?> input=json.readValue(body,Map.class);
            nonce=(String)input.get("nonce");
            if(nonce==null || !nonce.matches("[a-f0-9]{32}")) throw new IllegalArgumentException("invalid nonce");
            String action=(String)input.get("action");
            if(!initialized || state.equals("FAILED")) throw new IllegalStateException("reset permanently blocked");
            if(action.equals("block")) closeGate();
            else if(action.equals("reset")) {
                InstallProbe.assertInstalled(servletContext);
                Future<?> task=executor.submit(()->{try { reset(5000); } catch(Exception e) { throw new CompletionException(e); }});
                try { task.get(30000,TimeUnit.MILLISECONDS); }
                catch(Exception e) { task.cancel(true);throw e; }
            } else if(action.equals("authorize")) {
                boolean probes="1".equals(System.getenv("KAGENT_RESET_TEST_PROBES"));
                if(!state.equals("CLOSED") || (generation==0 && !probes) || active!=0) throw new IllegalStateException("not quiescent");
                lifecycle.verify();
                String requested=(String)input.get("route");
                long seconds=((Number)input.get("lease_seconds")).longValue();
                boolean testRoute="1".equals(System.getenv("KAGENT_RESET_TEST_PROBES")) && "/__kagent_probe".equals(requested);
                if(requested==null || !(testRoute || requested.matches("/(?:sqli|xss)-[0-9]{2}/BenchmarkTest[0-9]{5}")) || seconds<1 || seconds>3600)
                    throw new IllegalArgumentException("invalid case lease");
                synchronized(monitor) { route=requested;deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds);state="OPEN"; }
            } else if(!action.equals("status")) throw new IllegalArgumentException("unknown action");
            resp.setContentType("application/json");json.writeValue(resp.getOutputStream(),evidence(nonce,started));
        } catch(Exception failure) {
            servletContext.log("logical reset failed; admission remains closed",failure);
            synchronized(monitor) { state="FAILED";route=null;deadline=0; }
            resp.setStatus(503);resp.setContentType("application/json");
            Map<String,Object> result=evidence(nonce,started);result.put("verified",false);result.put("error",failure.getClass().getSimpleName());
            json.writeValue(resp.getOutputStream(),result);
        }
    }
    @Override public void destroy() { closeGate();executor.shutdownNow(); }
}
