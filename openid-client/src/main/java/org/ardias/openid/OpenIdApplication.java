package org.ardias.openid;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

public class OpenIdApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<>();
        classes.add(OpenIdService.class);
        return classes;
    }
}
