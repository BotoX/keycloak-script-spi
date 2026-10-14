package kc.ScriptBased;

import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ScriptModel;
import org.keycloak.models.UserModel;
import org.keycloak.scripting.InvocableScriptAdapter;
import org.keycloak.scripting.ScriptExecutionException;
import org.keycloak.scripting.ScriptingProvider;

import org.jboss.logging.Logger;

/**
 * A {@link ConditionalAuthenticator} that executes a configured script to determine
 * if an authentication sub-flow should be executed.
 * <p>
 * Scripts must provide the following function:
 * <ol>
 * <li>{@code matchCondition(..)} which is called from {@link ConditionalAuthenticator#matchCondition(AuthenticationFlowContext)}</li>
 * </ol>
 * </p>
 * <p>
 * The script must return a boolean value (true or false).
 * </p>
 */
public class ScriptBasedConditionalAuthenticator implements ConditionalAuthenticator {

    private static final Logger LOGGER = Logger.getLogger(ScriptBasedConditionalAuthenticator.class);

    static final String SCRIPT_CODE = "scriptCode";
    static final String SCRIPT_NAME = "scriptName";
    static final String SCRIPT_DESCRIPTION = "scriptDescription";

    static final String MATCH_CONDITION_FUNCTION_NAME = "matchCondition";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        if (!hasAuthenticatorConfig(context)) {
            // Default to false to avoid accidentally executing sensitive flows if unconfigured
            LOGGER.warn("Script condition is unconfigured. Defaulting to false.");
            return false;
        }

        InvocableScriptAdapter invocableScriptAdapter = getInvocableScriptAdapter(context);

        if (!invocableScriptAdapter.isDefined(MATCH_CONDITION_FUNCTION_NAME)) {
            LOGGER.error("Script does not define the required function: " + MATCH_CONDITION_FUNCTION_NAME);
            return false;
        }

        try {
            Object result = invocableScriptAdapter.invokeFunction(MATCH_CONDITION_FUNCTION_NAME, context);
            
            // Handle script return type safely
            if (result instanceof Boolean) {
                return (Boolean) result;
            }
            return "true".equalsIgnoreCase(String.valueOf(result));

        } catch (ScriptExecutionException e) {
            LOGGER.error("Error executing script condition", e);
            return false;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // NOOP for conditions
    }

    private boolean hasAuthenticatorConfig(AuthenticationFlowContext context) {
        if (context == null) return false;
        AuthenticatorConfigModel config = getAuthenticatorConfig(context);
        return config != null
                && config.getConfig() != null
                && !config.getConfig().isEmpty();
    }

    protected AuthenticatorConfigModel getAuthenticatorConfig(AuthenticationFlowContext context) {
        return context.getAuthenticatorConfig();
    }

    private InvocableScriptAdapter getInvocableScriptAdapter(AuthenticationFlowContext context) {

        Map<String, String> config = getAuthenticatorConfig(context).getConfig();

        String scriptName = config.get(SCRIPT_NAME);
        String scriptCode = config.get(SCRIPT_CODE);
        String scriptDescription = config.get(SCRIPT_DESCRIPTION);

        RealmModel realm = context.getRealm();
        ScriptingProvider scripting = context.getSession().getProvider(ScriptingProvider.class);

        ScriptModel script = scripting.createScript(realm.getId(), ScriptModel.TEXT_JAVASCRIPT, scriptName, scriptCode, scriptDescription);

        return scripting.prepareInvocableScript(script, bindings -> {
            bindings.put("script", script);
            bindings.put("realm", context.getRealm());
            bindings.put("user", context.getUser());
            bindings.put("session", context.getSession());
            bindings.put("httpRequest", context.getHttpRequest());
            bindings.put("authenticationSession", context.getAuthenticationSession());
            bindings.put("LOG", LOGGER);
        });
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }
}