/*******************************************************************************
 * Copyright (c) 2013 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.authentication.collective;

import java.security.cert.X509Certificate;

import com.ibm.ws.security.authentication.AuthenticationException;

/**
 * Plug-point for the collective to provide authentication checks to the
 * authentication flow.
 */
public interface CollectiveAuthenticationPlugin {

    /**
     * Determine if the X509Certificate chain represents a collective
     * certificate. A collective certificate should be handled by {@link #authenticateCertificateChain(X509Certificate[], boolean)}.
     * 
     * @param certChain
     * @return {@code true} if the certificate is a collective certificate, {@code false} otherwise.
     */
    boolean isCollectiveCertificateChain(X509Certificate[] certChain);

    /**
     * Determine if the X509Certificate chain represents a collective
     * certificate. A collective certificate should be handled by {@link #authenticateCertificateChain(X509Certificate[], boolean)}.
     * 
     * @param certChain
     * @return {@code true} if the certificate is a collective certificate, {@code false} otherwise.
     */
    boolean isCollectiveCACertificate(X509Certificate[] certChain);

    /**
     * Determine if the X509Certificate chain represents an authenticated
     * collective identity. The certificate chain must reflect a currently
     * registered collective member.
     * 
     * @param certChain
     * @param collectiveCert
     * @throws AuthenticationException if the certificate is not an authenticated collective certificate
     */
    void authenticateCertificateChain(X509Certificate certChain[], boolean collectiveCert) throws AuthenticationException;

    /**
     * OLGH8933 adds the capability to cache Subjects created via a certificate login. However, we never want to cache Collective certificate Subjects.
     * Caching creates problems for processing when CollectiveAuthenticationPluginImpl.isFlaggedForNoLogin=true.
     * Once the Subject is cached, that check is no longer performed. For now, every Collective certificate login
     * will not cache the Subject to ensure NOLOGIN is enforced.
     * @return True: Cache Collective certificate Subjects. 
     *         False: Don't cache Collective certificate Subjects.
     */
    boolean shouldCacheCollectiveCertificate();
    
    /**
     * OLGH8933 adds the capability to cache Subjects created via a certificate login. However, we never want to cache Collective certificate Subjects.
     * Caching creates problems for processing when CollectiveAuthenticationPluginImpl.isFlaggedForNoLogin=true.
     * Once the Subject is cached, that check is no longer performed. For now, every Collective certificate login
     * will not cache the Subject to ensure NOLOGIN is enforced.
     * @param  True: Cache Collective certificate Subjects. 
     *         False: Don't cache Collective certificate Subjects.
     */
    void setCacheCollectiveCertificate(boolean ccc);
}
