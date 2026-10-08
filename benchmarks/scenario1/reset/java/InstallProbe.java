package org.kagent.scenario1.reset;

import java.lang.reflect.Field;
import javax.servlet.ServletContext;
import org.apache.catalina.Container;
import org.apache.catalina.core.StandardContext;

/** Assert Tomcat's live container hierarchy, original filters and lifecycle listener. */
final class InstallProbe {
    static StandardContext context(ServletContext facade) throws Exception {
        Field f=facade.getClass().getDeclaredField("context");f.setAccessible(true);
        Object application=f.get(facade);
        f=application.getClass().getDeclaredField("context");f.setAccessible(true);
        StandardContext live=(StandardContext)f.get(application);
        Container host=live.getParent();
        StandardContext found=null;
        for(Container child:host.findChildren()) if(child.getName().equals(live.getName())) found=(StandardContext)child;
        if(found!=live || live.getLoader().getClassLoader()!=ResetGate.class.getClassLoader())
            throw new IllegalStateException("live application container identity mismatch");
        return live;
    }
    static void assertInstalled(ServletContext facade) throws Exception {
        StandardContext context=context(facade);
        for(String original:new String[]{"DBRollback","addMoreSecureResponseHeaders","httpHeaderSecurity"}) {
            Object config=context.findFilterConfig(original);
            java.lang.reflect.Method getter=config==null?null:config.getClass().getDeclaredMethod("getFilter");
            if(getter!=null) getter.setAccessible(true);
            if(config==null || getter.invoke(config)==null)
                throw new IllegalStateException("original filter instance missing: "+original);
        }
        boolean tracked=false;
        for(Object listener:context.getApplicationLifecycleListeners()) if(listener instanceof ResetGate) tracked=true;
        if(!tracked) throw new IllegalStateException("session lifecycle listener missing");
    }
}
