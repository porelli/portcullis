<#-- Copy of Keycloak 26.8.1 themes/keycloak.v2/login/webauthn-register.ftl
     (Apache-2.0). The one Portcullis change: the input gets portcullisHints,
     the JSON array the sign-in extension's registration action sets
     (contract §8.1), read by resources/js/webauthnRegister.js. Keep in sync
     when the Keycloak version of ghcr.io/porelli/portcullis-keycloak is
     upgraded. -->
<#import "template.ftl" as layout>
<#import "password-commons.ftl" as passwordCommons>
<#import "buttons.ftl" as buttons>

<@layout.registrationLayout; section>
    <#if section = "title">
        title
    <#elseif section = "header">
        ${msg("webauthn-registration-title")}
    <#elseif section = "form">
    <div class="${properties.kcFormClass!}">
        <form id="register" action="${url.loginAction}" method="post" >
            <div class="${properties.kcFormGroupClass!}">
                <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
                <input type="hidden" id="attestationObject" name="attestationObject"/>
                <input type="hidden" id="publicKeyCredentialId" name="publicKeyCredentialId"/>
                <input type="hidden" id="authenticatorLabel" name="authenticatorLabel"/>
                <input type="hidden" id="transports" name="transports"/>
                <input type="hidden" id="authenticatorAttachment" name="authenticatorAttachment"/>
                <input type="hidden" id="error" name="error"/>
                <@passwordCommons.logoutOtherSessions/>
            </div>
        </form>

        <script type="module">
            <#outputformat "JavaScript">
            import { registerByWebAuthn } from "${url.resourcesPath}/js/webauthnRegister.js";
            const registerButton = document.getElementById('registerWebAuthn');
            registerButton.addEventListener("click", function() {
                const input = {
                    challenge : ${challenge?c},
                    userid : ${userid?c},
                    username : ${username?c},
                    signatureAlgorithms : [<#list signatureAlgorithms as sigAlg>${sigAlg?c},</#list>],
                    rpEntityName : ${rpEntityName?c},
                    rpId : ${rpId?c},
                    attestationConveyancePreference : ${attestationConveyancePreference?c},
                    authenticatorAttachment : ${authenticatorAttachment?c},
                    requireResidentKey : ${requireResidentKey?c},
                    residentKey : ${residentKey?c},
                    userVerificationRequirement : ${userVerificationRequirement?c},
                    createTimeout : ${createTimeout?c},
                    excludeCredentialIds : ${excludeCredentialIds?c},
                    initLabel : ${msg("webauthn-registration-init-label")?c},
                    initLabelPrompt : ${msg("webauthn-registration-init-label-prompt")?c},
                    errmsg : ${msg("webauthn-unsupported-browser-text")?c},
                    portcullisHints : ${(portcullisHints!"[]")?c}
                };
                registerByWebAuthn(input);
            },  { once: true });
            </#outputformat>
        </script>

            <@buttons.actionGroup horizontal=true>
                <@buttons.button id="registerWebAuthn" label="doRegisterSecurityKey"/>
                <#if !isSetRetry?has_content && isAppInitiatedAction?has_content>
                    <form class="${properties.kcFormClass!}" action="${url.loginAction}"
                          id="kc-webauthn-settings-form" method="post">
                        <@buttons.button id="cancelWebAuthnAIA" name="cancel-aia" label="doCancel" type="secondary"/>
                    </form>
                </#if>
            </@buttons.actionGroup>
    </div>
    </#if>
</@layout.registrationLayout>
