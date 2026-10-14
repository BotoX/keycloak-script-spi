package kc.ScriptBased;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

import static java.util.Arrays.asList;

import static kc.ScriptBased.ScriptBasedConditionalAuthenticator.SCRIPT_CODE;
import static kc.ScriptBased.ScriptBasedConditionalAuthenticator.SCRIPT_DESCRIPTION;
import static kc.ScriptBased.ScriptBasedConditionalAuthenticator.SCRIPT_NAME;
import static org.keycloak.provider.ProviderConfigProperty.SCRIPT_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

/**
 * A {@link ConditionalAuthenticatorFactory} for {@link ScriptBasedConditionalAuthenticator}s.
 */
public class ScriptBasedConditionalAuthenticatorFactory implements ConditionalAuthenticatorFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "condition-script-based";

    static final ScriptBasedConditionalAuthenticator SINGLETON = new ScriptBasedConditionalAuthenticator();

    @Override
    public ConditionalAuthenticator getSingleton() {
        return SINGLETON;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED};
    }

    @Override
    public String getDisplayType() {
        return "Condition - Script";
    }

    @Override
    public String getHelpText() {
        return "Script based condition. Allows defining custom conditional flow logic via JavaScript.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        ProviderConfigProperty name = new ProviderConfigProperty();
        name.setType(STRING_TYPE);
        name.setName(SCRIPT_NAME);
        name.setLabel("Script Name");
        name.setHelpText("The name of the script used for the condition.");

        ProviderConfigProperty description = new ProviderConfigProperty();
        description.setType(STRING_TYPE);
        description.setName(SCRIPT_DESCRIPTION);
        description.setLabel("Script Description");
        description.setHelpText("The description of the script used for the condition.");

        ProviderConfigProperty script = new ProviderConfigProperty();
        script.setType(SCRIPT_TYPE);
        script.setName(SCRIPT_CODE);
        script.setReadOnly(true);
        script.setLabel("Script Source");

        script.setHelpText("The script used to evaluate the condition. Scripts must define a function named 'matchCondition(context)' that returns true or false.\n" +
                "Available variables: 'script', 'realm', 'user', 'session', 'authenticationSession', 'httpRequest', 'LOG'");

        return asList(name, description, script);
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.SCRIPTS);
    }
}
