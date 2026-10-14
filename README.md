This project registers the built-in:
- ScriptBasedOIDCProtocolMapper
- ScriptBasedMapper (SAML)
- ScriptBasedAuthenticatorFactory
via SPI.

It simply contains the service files:
- META-INF/services/org.keycloak.protocol.ProtocolMapper
with the entries:
- org.keycloak.protocol.oidc.mappers.ScriptBasedOIDCProtocolMapper
- org.keycloak.protocol.saml.mappers.ScriptBasedMapper

And the service file:
- org.keycloak.authentication.AuthenticatorFactory
with the entry:
- org.keycloak.authentication.authenticators.browser.ScriptBasedAuthenticatorFactory


It also implements a new ScriptBasedConditionalAuthenticator, which can be used as follows:

```
function matchCondition(context) {
    if (user && user.getAttribute("example") && user.getAttribute("example").contains("true")) {
        return true; 
    }

    return false; 
}
```
