package com.datapipe.jenkins.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.json.JsonArray;
import com.bettercloud.vault.json.JsonObject;
import com.bettercloud.vault.json.JsonValue;
import com.bettercloud.vault.json.WriterConfig;
import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.response.LookupResponse;
import com.bettercloud.vault.response.VaultResponse;
import com.bettercloud.vault.rest.RestResponse;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.configuration.VaultConfigResolver;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.AbstractVaultTokenCredentialWithExpiration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.datapipe.jenkins.vault.model.VaultSecretValue;
import hudson.EnvVars;
import hudson.ExtensionList;
import hudson.Util;
import hudson.model.Run;
import hudson.security.ACL;
import java.io.PrintStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

public class VaultAccessor implements Serializable {

    private final static Logger LOGGER = Logger
        .getLogger(VaultAccessor.class.getName());

    private static final long serialVersionUID = 1L;

    private VaultConfig config;
    private VaultCredential credential;
    private int maxRetries = 0;
    private int retryIntervalMilliseconds = 1000;

    private transient Vault vault;

    public VaultAccessor() {
        this.config = new VaultConfig();
    }

    public VaultAccessor(VaultConfig config, VaultCredential credential) {
        this.config = config;
        this.credential = credential;
    }

    public VaultAccessor init() {
        try {
            config.build();

            if (credential == null) {
                vault = new Vault(config);
            } else {
                vault = credential.authorizeWithVault(config);
            }

            vault.withRetries(maxRetries, retryIntervalMilliseconds);
        } catch (VaultException e) {
            throw new VaultPluginException("failed to connect to vault", e);
        }
        return this;
    }

    public VaultConfig getConfig() {
        return config;
    }

    public void setConfig(VaultConfig config) {
        this.config = config;
    }

    public VaultCredential getCredential() {
        return credential;
    }

    public void setCredential(VaultCredential credential) {
        this.credential = credential;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    public int getRetryIntervalMilliseconds() {
        return retryIntervalMilliseconds;
    }

    public void setRetryIntervalMilliseconds(int retryIntervalMilliseconds) {
        this.retryIntervalMilliseconds = retryIntervalMilliseconds;
    }

    @Deprecated
    public void init(String url, VaultCredential credential) {
        config.address(url);
        this.credential = credential;
    }

    public LogicalResponse read(String path, Integer engineVersion) {
        try {
            this.config.engineVersion(engineVersion);
            return vault.logical().read(path);
        } catch (VaultException e) {
            throw new VaultPluginException(
                "could not read from vault: " + e.getMessage() + " at path: " + path, e);
        }
    }

    public VaultResponse revoke(String leaseId) {
        try {
            return vault.leases().revoke(leaseId);
        } catch (VaultException e) {
            throw new VaultPluginException(
                "could not revoke vault lease (" + leaseId + "):" + e.getMessage());
        }
    }

    public static Map<String, String> retrieveVaultSecrets(Run<?,?> run, PrintStream logger, EnvVars envVars, VaultAccessor vaultAccessor, VaultConfiguration initialConfiguration, List<VaultSecret> vaultSecrets) {
        Map<String, String> overrides = new HashMap<>();

        VaultConfiguration config = pullAndMergeConfiguration(run, initialConfiguration);
        String url = config.getVaultUrl();

        if (StringUtils.isBlank(url)) {
            throw new VaultPluginException(
                "The vault url was not configured - please specify the vault url to use.");
        }

        VaultConfig vaultConfig = config.getVaultConfig();
        VaultCredential credential = config.getVaultCredential();
        if (credential == null) {
            credential = retrieveVaultCredentials(run, config);
        }

        String prefixPath = StringUtils.isBlank(config.getPrefixPath())
            ? ""
            : Util.ensureEndsWith(envVars.expand(config.getPrefixPath()), "/");

        if (vaultAccessor == null) {
            vaultAccessor = new VaultAccessor();
        }
        vaultAccessor.setConfig(vaultConfig);
        vaultAccessor.setCredential(credential);
        vaultAccessor.setMaxRetries(config.getMaxRetries());
        vaultAccessor.setRetryIntervalMilliseconds(config.getRetryIntervalMilliseconds());
        vaultAccessor.init();

        for (VaultSecret vaultSecret : vaultSecrets) {
            String path = prefixPath + envVars.expand(vaultSecret.getPath());
            logger.printf("Retrieving secret: %s%n", path);
            Integer engineVersion = Optional.ofNullable(vaultSecret.getEngineVersion())
                .orElse(config.getEngineVersion());
            try {
                LogicalResponse response = vaultAccessor.read(path, engineVersion);
                if (responseHasErrors(config, logger, path, response)) {
                    continue;
                }
                Map<String, String> values = response.getData();
                for (VaultSecretValue value : vaultSecret.getSecretValues()) {
                    String vaultKey = value.getVaultKey();
                    String secret = values.get(vaultKey);
                    if (StringUtils.isBlank(secret) && value.getIsRequired()) {
                        throw new IllegalArgumentException(
                            "Vault Secret " + vaultKey + " at " + path
                                + " is either null or empty. Please check the Secret in Vault.");
                    }
                    overrides.put(value.getEnvVar(), secret);
                }
            } catch (VaultPluginException ex) {
                VaultException e = (VaultException) ex.getCause();
                if (e != null) {
                    throw new VaultPluginException(String
                        .format("Vault response returned %d for secret path %s",
                            e.getHttpStatusCode(), path),
                        e);
                }
                throw ex;
            }
        }

        return overrides;
    }

    public static VaultCredential retrieveVaultCredentials(Run build, VaultConfiguration config) {
        if (Jenkins.getInstanceOrNull() != null) {
            String id = config.getVaultCredentialId();
            if (StringUtils.isBlank(id)) {
                throw new VaultPluginException(
                    "The credential id was not configured - please specify the credentials to use.");
            }
            List<VaultCredential> credentials = CredentialsProvider
                .lookupCredentials(VaultCredential.class, build.getParent(), ACL.SYSTEM,
                    Collections.emptyList());
            VaultCredential credential = CredentialsMatchers
                .firstOrNull(credentials, new IdMatcher(id));

            if (credential == null) {
                throw new CredentialsUnavailableException(id);
            }

            return credential;
        }

        return null;
    }

    public static boolean responseHasErrors(VaultConfiguration configuration, PrintStream logger,
        String path, LogicalResponse response) {
        RestResponse restResponse = response.getRestResponse();
        if (restResponse == null) {
            return false;
        }
        int status = restResponse.getStatus();
        if (status == 403) {
            JsonValue jsonResponse = Json.parse(new String(restResponse.getBody(), StandardCharsets.UTF_8));
            final String prettyJsonResponse = jsonResponse.toString(WriterConfig.PRETTY_PRINT);

            try {
                Vault vault = new Vault(configuration.getVaultConfig());
                LookupResponse selfLookupResponse = vault.auth().lookupSelf();
                final String tokenId = selfLookupResponse.getId();
                final String tokenSelfLookupJson = new String(selfLookupResponse.getRestResponse().getBody(), StandardCharsets.UTF_8);
                final JsonObject jsonObject = Json.parse(tokenSelfLookupJson).asObject();
                final String dataJsonObject = jsonObject.get("data").toString(WriterConfig.PRETTY_PRINT);
                LOGGER.log(Level.FINE, String.format("CA-2586: Auth token %s got %d: %s", tokenId, status, prettyJsonResponse));
                LOGGER.log(Level.FINE, "CA-2586: Auth token self-lookup: " + dataJsonObject);
            } catch (Throwable e) {
                LOGGER.log(Level.FINE, String.format("CA-2586: Auth token got %d: %s", status, prettyJsonResponse));
                LOGGER.log(Level.FINE, String.format("CA-2586: Error in self-lookup call on %d token: %s", status, e));
            }

            logger.printf("Access denied to Vault Secrets at '%s'%n", path);
            return true;
        } else if (status == 404) {
            if (configuration.getFailIfNotFound()) {
                throw new VaultPluginException(
                    String.format("Vault credentials not found for '%s'", path));
            } else {
                logger.printf("Vault credentials not found for '%s'%n", path);
                return true;
            }
        } else if (status >= 400) {
            String errors = Optional
                .of(Json.parse(new String(restResponse.getBody(), StandardCharsets.UTF_8))).map(
                    JsonValue::asObject)
                .map(j -> j.get("errors")).map(JsonValue::asArray).map(JsonArray::values)
                .map(j -> j.stream().map(JsonValue::asString).collect(Collectors.joining("\n")))
                .orElse("");
            logger.printf("Vault responded with %d error code.%n", status);
            if (StringUtils.isNotBlank(errors)) {
                logger.printf("Vault responded with errors: %s%n", errors);
            }
            return true;
        }
        return false;
    }

    public static VaultConfiguration pullAndMergeConfiguration(Run<?, ?> build,
        VaultConfiguration buildConfiguration) {
        VaultConfiguration configuration = buildConfiguration;
        for (VaultConfigResolver resolver : ExtensionList.lookup(VaultConfigResolver.class)) {
            if (configuration != null) {
                configuration = configuration
                    .mergeWithParent(resolver.forJob(build.getParent()));
            } else {
                configuration = resolver.forJob(build.getParent());
            }
        }
        if (configuration == null) {
            throw new VaultPluginException(
                "No configuration found - please configure the VaultPlugin.");
        }
        configuration.fixDefaults();

        return configuration;
    }
}
