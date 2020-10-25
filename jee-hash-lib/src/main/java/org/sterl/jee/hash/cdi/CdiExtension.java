package org.sterl.jee.hash.cdi;

import java.util.logging.Logger;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;

import org.sterl.jee.hash.BCryptAndPbkdf2PasswordHashImpl;

public class CdiExtension implements Extension {

    private static final Logger LOGGER = Logger.getLogger(CdiExtension.class.getName());

    public void register(@Observes BeforeBeanDiscovery beforeBean, BeanManager beanManager) {
        beforeBean.addAnnotatedType(
                beanManager.createAnnotatedType(BCryptAndPbkdf2PasswordHashImpl.class), 
                BCryptAndPbkdf2PasswordHashImpl.class.getName());
        
        LOGGER.fine("BCryptAndPbkdf2PasswordHash registered.");
    }

}
