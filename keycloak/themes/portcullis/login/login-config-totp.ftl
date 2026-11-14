<#-- Copy of Keycloak 26.8.1 themes/keycloak.v2/login/login-config-totp.ftl
     (Apache-2.0). The Portcullis changes (contract §8.1 "Authenticator-app
     codes"): the device name is prefilled "Authenticator <yyyy-MM-dd
     HH:mm:ss>" (Keycloak refuses a second credential with the same label),
     and step 1 names the apps that work with the realm policy (HmacSHA1,
     6 digits, 30 s). Everything else is verbatim: the QR code
     (#kc-totp-secret-qr-code) and manual key (#kc-totp-secret-key) ids, the
     hidden totpSecret input and the mode handling (the required action's
     processAction reads totpSecret, totp, userLabel, mode and
     logout-sessions). Keep in sync when the Keycloak version of
     ghcr.io/porelli/portcullis-keycloak is upgraded. -->
<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "password-commons.ftl" as passwordCommons>
<#import "qr-code.ftl" as qr>
<@layout.registrationLayout displayRequiredFields=false displayMessage=!messagesPerField.existsError('totp','userLabel'); section>
<!-- template: login-config-totp.ftl -->

    <#if section = "header">
        ${msg("loginTotpTitle")}
    <#elseif section = "form">
        <ol id="kc-totp-settings" class="pf-v5-c-list pf-v5-u-mb-md">
            <li>
                <p>${msg("portcullisTotpStep1")}</p>

                <ul id="kc-totp-supported-apps">
                    <#list ["Google Authenticator", "Microsoft Authenticator", "Authy", "1Password", "Bitwarden", "FreeOTP", "Aegis"] as app>
                        <li>${app}</li>
                    </#list>
                </ul>
            </li>

            <#if mode?? && mode = "manual">
                <li>
                    <p>${msg("loginTotpManualStep2")}</p>
                    <p><span id="kc-totp-secret-key">${totp.totpSecretEncoded}</span></p>
                    <p><a href="${totp.qrUrl}" id="mode-barcode">${msg("loginTotpScanBarcode")}</a></p>
                </li>
                <li>
                    <p>${msg("loginTotpManualStep3")}</p>
                    <p>
                    <ul>
                        <li id="kc-totp-type">${msg("loginTotpType")}: ${msg("loginTotp." + totp.policy.type)}</li>
                        <li id="kc-totp-algorithm">${msg("loginTotpAlgorithm")}: ${totp.policy.getAlgorithmKey()}</li>
                        <li id="kc-totp-digits">${msg("loginTotpDigits")}: ${totp.policy.digits}</li>
                        <#if totp.policy.type = "totp">
                            <li id="kc-totp-period">${msg("loginTotpInterval")}: ${totp.policy.period}</li>
                        <#elseif totp.policy.type = "hotp">
                            <li id="kc-totp-counter">${msg("loginTotpCounter")}: ${totp.policy.initialCounter}</li>
                        </#if>
                    </ul>
                    </p>
                </li>
            <#else>
                <li>
                    <p>${msg("loginTotpStep2")}</p>
                    <@qr.qrCode id="kc-totp-secret-qr-code" content=totp.totpSecretQrCode alt=msg("loginTotpStep2")>
                        <a href="${totp.manualUrl}" id="mode-manual">${msg("loginTotpUnableToScan")}</a>
                    </@qr.qrCode>
                </li>
            </#if>
            <li>
                <p>${msg("loginTotpStep3")}</p>
                <p>${msg("loginTotpStep3DeviceName")}</p>
            </li>
        </ol>

        <form action="${url.loginAction}" class="${properties.kcFormClass!}" id="kc-totp-settings-form" method="post" novalidate="novalidate">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelClass!}">
                    <label class="pf-v5-c-form__label" for="form-vertical-name">
                        <span class="pf-v5-c-form__label-text">${msg("authenticatorCode")}</span>&nbsp;<span class="pf-v5-c-form__label-required" aria-hidden="true">&#42;</span>
                    </label>
                </div>
                <div class="${properties.kcInputClass!} <#if messagesPerField.existsError('totp')>pf-m-error</#if>">
                    <input type="text" required id="totp" name="totp" autocomplete="one-time-code"
                           aria-invalid="<#if messagesPerField.existsError('totp')>true</#if>"
                           inputmode="numeric"
                    />

                    <@field.errorIcon error=messagesPerField.get('totp')/>
                </div>
                <#if messagesPerField.existsError('totp')>
                    <span id="input-error-otp-code" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                        ${messagesPerField.get('totp')}
                    </span>
                </#if>
                <input type="hidden" id="totpSecret" name="totpSecret" value="${totp.totpSecret}" />
                <#if mode??><input type="hidden" id="mode" name="mode" value="${mode}"/></#if>
            </div>
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelClass!}">
                    <label class="pf-v5-c-form__label" for="form-vertical-name">
                        <span class="pf-v5-c-form__label-text">${msg("loginTotpDeviceName")}</span><#if totp.otpCredentials?size gte 1>&nbsp;<span class="pf-v5-c-form__label-required" aria-hidden="true">&#42;</span></#if>
                    </label>
                </div>

                <div class="${properties.kcInputClass!} <#if messagesPerField.existsError('userLabel')>pf-m-error</#if>">
                    <input type="text" id="userLabel" name="userLabel" autocomplete="off"
                           value="${msg("portcullisTotpDeviceDefault")} ${.now?string("yyyy-MM-dd HH:mm:ss")}"
                           aria-invalid="<#if messagesPerField.existsError('userLabel')>true</#if>"
                    />

                    <@field.errorIcon error=messagesPerField.get('userLabel')/>
                </div>
                <#if messagesPerField.existsError('userLabel')>
                    <span id="input-error-otp-label" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                        ${messagesPerField.get('userLabel')}
                    </span>
                </#if>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <@passwordCommons.logoutOtherSessions/>
            </div>

            <#if isAppInitiatedAction??>
                <@buttons.actionGroup horizontal=true>
                    <@buttons.button id="saveTOTPBtn" label="doSubmit" />
                    <@buttons.button id="cancelTOTPBtn" name="cancel-aia" label="doCancel" type="secondary" value="true" />
                </@buttons.actionGroup>
            <#else>
                <@buttons.actionGroup>
                    <@buttons.button id="saveTOTPBtn" label="doSubmit" />
                </@buttons.actionGroup>
            </#if>
        </form>
    </#if>
</@layout.registrationLayout>
