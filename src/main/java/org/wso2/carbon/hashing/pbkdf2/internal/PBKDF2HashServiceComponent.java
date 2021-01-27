package org.wso2.carbon.hashing.pbkdf2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;

import org.wso2.carbon.hashing.pbkdf2.PBKDF2HashCalculator;
import org.wso2.carbon.user.core.hashing.HashCalculator;

/**
 * This class contains the PBKDF2 hashing service component.
 */
@Component(
        name = "org.wso2.carbon.core.pbkdf2",
        immediate = true
)
public class PBKDF2HashServiceComponent {

    private static Log log = LogFactory.getLog(PBKDF2HashServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        HashCalculator hashCalculator = new PBKDF2HashCalculator();
        ctxt.getBundleContext().registerService(HashCalculator.class.getName(),
                hashCalculator, null);
        log.info("PBKDF2 bundle activated successfully..");
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("PBKDF2 bundle is deactivated ");
        }
    }

}
