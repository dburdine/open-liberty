/*******************************************************************************
 * Copyright (c) 2019 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.authentication.internal.cache.keyproviders;

import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

import com.ibm.ws.security.authentication.cache.CacheContext;
import com.ibm.ws.security.authentication.cache.CacheKeyProvider;
import com.ibm.ws.security.authentication.collective.CollectiveAuthenticationPlugin;
import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;

/**
 *
 */
public class X509CertCacheKeyProvider implements CacheKeyProvider {

    private static CollectiveAuthenticationPlugin cap = null;
    public static final String KEY_COLLECTIVE_AUTHENTICATON_PLUGIN = "collectiveAuthenticationPlugin";
    private static final AtomicServiceReference<CollectiveAuthenticationPlugin> collectiveAuthenticationPlugin = new AtomicServiceReference<CollectiveAuthenticationPlugin>(KEY_COLLECTIVE_AUTHENTICATON_PLUGIN);

    @Reference(service = CollectiveAuthenticationPlugin.class,
               name = KEY_COLLECTIVE_AUTHENTICATON_PLUGIN,
               policy = ReferencePolicy.DYNAMIC,
               policyOption = ReferencePolicyOption.GREEDY)
    public void setCollectiveAuthenticationPlugin(CollectiveAuthenticationPlugin cap) {
        this.cap = cap;
    }

    public void unsetCollectiveAuthenticationPlugin(CollectiveAuthenticationPlugin cap) {
        if (cap == this.cap) {
            this.cap = null;
        }
    }

    @Override
    public Object provideKey(CacheContext cacheContext) {
        int certHash;
        if (cap == null || (cap != null && cap.shouldCacheCollectiveCertificate() == true)) {
            final java.security.cert.X509Certificate[] cert_chain = (java.security.cert.X509Certificate[]) cacheContext.getCertChain();
            if (cert_chain != null) {
                certHash = ((java.security.cert.Certificate) cert_chain[0]).hashCode();
                return certHash;
            }
        }
        return null;
    }

}
