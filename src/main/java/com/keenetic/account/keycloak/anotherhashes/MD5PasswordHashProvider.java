/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.keenetic.account.keycloak.anotherhashes;

import java.math.BigInteger;
import java.security.MessageDigest;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * @author <a href="mailto:hokum@dived.me">Andrey Kotov</a>
 */
public class MD5PasswordHashProvider implements PasswordHashProvider {

    // Reference is
    // https://github.com/keycloak/keycloak/blob/master/server-spi-private/src/main/java/org/keycloak/credential/hash/Pbkdf2PasswordHashProvider.java

    private final String providerId;

    public MD5PasswordHashProvider(String providerId) {
        this.providerId = providerId;
    }

    @Override
    public boolean policyCheck(PasswordPolicy passwordPolicy, PasswordCredentialModel passwordCredentialModel) {
        return providerId.equals(passwordCredentialModel.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        String encodedPassword = encode(rawPassword, iterations);
        return PasswordCredentialModel.createFromValues(providerId, null, iterations, encodedPassword);
    }

    @Override
    public String encode(String rawPassword, int iterations) {
        String hashedPassword = "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(rawPassword.getBytes());
            BigInteger digestInt = new BigInteger(1,md.digest());
            StringBuilder sbZeroes = new StringBuilder(digestInt.toString(16));
            while(sbZeroes.length() < 32 ){ // add leading zeroes to 32 chars
                sbZeroes.insert(0, "0");
            }
            hashedPassword = sbZeroes.toString();
        } catch (java.security.NoSuchAlgorithmException ignored) {}
        return hashedPassword;
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel passwordCredentialModel) {
        return encode(rawPassword, passwordCredentialModel.getPasswordCredentialData().getHashIterations())
                .equals(passwordCredentialModel.getPasswordSecretData().getValue());
    }

    @Override
    public void close() {

    }

}
