package stalwart

import "strings"

// Permission lists (contract §19.4, §19.6, §19.11; the names are Stalwart
// v1.1.0's `Permission` enum, checked against the schema snapshot).

// IMAPPermissions is every imap* permission of v1.1.0 (imapAuthenticate
// included; P52: 31).
var IMAPPermissions = []string{
	"imapAuthenticate", "imapAclGet", "imapAclSet", "imapMyRights", "imapListRights", "imapAppend",
	"imapCapability", "imapId", "imapCopy", "imapMove", "imapCreate", "imapDelete", "imapEnable",
	"imapExpunge", "imapFetch", "imapIdle", "imapList", "imapLsub", "imapNamespace", "imapRename",
	"imapSearch", "imapSort", "imapSelect", "imapExamine", "imapStatus", "imapStore", "imapSubscribe",
	"imapThread", "imapMetadataGet", "imapMetadataSet", "imapMetadataPrivate",
}

// MailPasswordPermissions is a mail password's Replace list and the default
// user role: authenticate, emailSend, emailReceive and every imap*.
var MailPasswordPermissions = append([]string{"authenticate", "emailSend", "emailReceive"}, IMAPPermissions...)

// ExportPermissions is the export password's Replace list (M5).
var ExportPermissions = []string{"authenticate", "imapAuthenticate", "imapList", "imapSelect", "imapExamine", "imapFetch", "imapStatus"}

// MailctlRolePermissions is the role portcullis-mailctl (P1 widened):
// its own work, plus exactly the sets it grants (Stalwart refuses to grant
// a permission the caller lacks). Never sysApiKey*, sysRole*, jmap*, dav*,
// sieve*, pop3*: the key can't widen itself.
var MailctlRolePermissions = func() []string {
	own := []string{
		"authenticate", "impersonate",
		"sysAccountGet", "sysAccountCreate", "sysAccountUpdate", "sysAccountDestroy", "sysAccountQuery",
		"sysDomainGet", "sysDomainCreate", "sysDomainUpdate", "sysDomainDestroy", "sysDomainQuery",
		"sysDkimSignatureGet", "sysDkimSignatureCreate", "sysDkimSignatureUpdate", "sysDkimSignatureDestroy", "sysDkimSignatureQuery",
		"sysAppPasswordGet", "sysAppPasswordCreate", "sysAppPasswordUpdate", "sysAppPasswordDestroy", "sysAppPasswordQuery",
		"sysMailingListGet", "sysMailingListCreate", "sysMailingListUpdate", "sysMailingListDestroy", "sysMailingListQuery",
		"sysQueuedMessageGet", "sysQueuedMessageQuery", "sysCertificateGet", "sysCertificateQuery",
		"sysActionCreate", "actionReloadSettings", "actionReloadTlsCertificates", "actionInvalidateCaches", "actionReloadLookupStores",
		"sysDmarcExternalReportGet", "sysDmarcExternalReportQuery", "sysTlsExternalReportGet", "sysTlsExternalReportQuery",
		"sysSpamSettingsGet", "sysSpamSettingsUpdate",
		// The vendored rules' import (SpamFilterMaintenance updateRules:
		// the task-type permission too, Stalwart refuses it otherwise; the
		// task read back until it is done) and its proof (every vendored
		// rule name present).
		"sysTaskCreate", "sysTaskGet", "taskSpamFilterMaintenance", "sysSpamRuleGet", "sysSpamRuleQuery",
		"sysMemoryLookupKeyGet", "sysMemoryLookupKeyCreate", "sysMemoryLookupKeyUpdate", "sysMemoryLookupKeyDestroy", "sysMemoryLookupKeyQuery",
		// Settings mailctl edits after the bootstrap: the spam rules'
		// external lookups (kept disabled), the DNSBL servers and sender
		// authentication (the Hub's DNSBL switches, degraded mode M9).
		"sysHttpLookupGet", "sysHttpLookupQuery", "sysHttpLookupUpdate",
		"sysSpamDnsblServerGet", "sysSpamDnsblServerQuery", "sysSpamDnsblServerUpdate",
		"sysSenderAuthGet", "sysSenderAuthUpdate",
		// Task 9: the outbound limit (rate_held), the DANE switch.
		"sysMtaOutboundThrottleGet", "sysMtaOutboundThrottleCreate", "sysMtaOutboundThrottleUpdate", "sysMtaOutboundThrottleDestroy", "sysMtaOutboundThrottleQuery",
		"sysMtaTlsStrategyGet", "sysMtaTlsStrategyQuery", "sysMtaTlsStrategyUpdate",
		// The per-account limits (MtaInboundThrottle) and, with
		// submission_lan_only, the SASL rule (MtaStageAuth).
		"sysMtaInboundThrottleGet", "sysMtaInboundThrottleCreate", "sysMtaInboundThrottleUpdate",
		"sysMtaInboundThrottleDestroy", "sysMtaInboundThrottleQuery",
		"sysMtaStageAuthGet", "sysMtaStageAuthUpdate",
		// MailState v2's part of the base plan (bootstrap.ApplyDoc): the
		// host name, the relay route and its TLS strategy, the outbound
		// strategy and degraded mode's sender authentication / security.
		"sysSystemSettingsGet", "sysSystemSettingsUpdate",
		"sysMtaRouteGet", "sysMtaRouteQuery", "sysMtaRouteCreate", "sysMtaRouteUpdate", "sysMtaRouteDestroy",
		"sysMtaTlsStrategyCreate", "sysMtaOutboundStrategyGet", "sysMtaOutboundStrategyUpdate",
		"sysSecurityGet", "sysSecurityUpdate",
		// An account is created with the built-in User role, and Stalwart
		// refuses to grant a role whose permissions the caller lacks: 1.1's
		// User role (after the role-permission update) holds the passkey
		// set, so the key holds it too (seen in core CI: every account
		// create refused "not authorized to grant permissions: sysPasskey…").
		"sysPasskeyGet", "sysPasskeyCreate", "sysPasskeyUpdate", "sysPasskeyDestroy", "sysPasskeyQuery",
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{own, MailPasswordPermissions, ExportPermissions} {
		for _, p := range l {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}()

// ViewerRolePermissions is the role portcullis-viewer: the read-only
// mail admin view (contract §19.13). authenticate plus the Get and Query
// permission of every management object of v1.1.0 except
// ViewerDenied's, and nothing else: no Create, Update, Destroy, action,
// task, live*, impersonate, jmap*, imap*, pop3*, sieve*, dav*, email* or
// fetchAnyBlob permission. Stalwart masks every secret field on a read
// ("****"; includeSecrets stays false), and the bootstrap job (the
// recovery admin) is the only one that can grant it: mailctl's own role
// lacks most of these reads and every sysRole* permission.
var ViewerRolePermissions = []string{
	"authenticate",
	"sysAccountGet", "sysAccountQuery", "sysAccountSettingsGet", "sysAcmeProviderGet", "sysAcmeProviderQuery",
	"sysAddressBookGet", "sysAiModelGet", "sysAiModelQuery", "sysAlertGet", "sysAlertQuery", "sysAllowedIpGet",
	"sysAllowedIpQuery", "sysApplicationGet", "sysApplicationQuery", "sysAsnGet", "sysAuthenticationGet",
	"sysBlobStoreGet", "sysBlockedIpGet", "sysBlockedIpQuery", "sysCacheGet", "sysCalendarGet",
	"sysCalendarAlarmGet", "sysCalendarSchedulingGet", "sysCertificateGet", "sysCertificateQuery",
	"sysClusterNodeGet", "sysClusterNodeQuery", "sysClusterRoleGet", "sysClusterRoleQuery",
	"sysCoordinatorGet", "sysDataRetentionGet", "sysDataStoreGet", "sysDirectoryGet", "sysDirectoryQuery",
	"sysDkimReportSettingsGet", "sysDkimSignatureGet", "sysDkimSignatureQuery", "sysDmarcReportSettingsGet",
	"sysDnsResolverGet", "sysDnsServerGet", "sysDnsServerQuery", "sysDomainGet", "sysDomainQuery",
	"sysDsnReportSettingsGet", "sysEmailGet", "sysEncryptionGet", "sysEventTracingLevelGet",
	"sysEventTracingLevelQuery", "sysExternalPublicKeyGet", "sysExternalPublicKeyQuery", "sysFileStorageGet",
	"sysHttpGet", "sysHttpFormGet", "sysHttpLookupGet", "sysHttpLookupQuery", "sysImapGet",
	"sysInMemoryStoreGet", "sysIndexQueueStatusGet", "sysIndexQueueStatusQuery", "sysJmapGet",
	"sysMailingListGet", "sysMailingListQuery", "sysMemoryLookupKeyGet", "sysMemoryLookupKeyQuery",
	"sysMemoryLookupKeyValueGet", "sysMemoryLookupKeyValueQuery", "sysMetadataGet", "sysMetricGet",
	"sysMetricQuery", "sysMetricsGet", "sysMetricsStoreGet", "sysMtaConnectionStrategyGet",
	"sysMtaConnectionStrategyQuery", "sysMtaDeliveryScheduleGet", "sysMtaDeliveryScheduleQuery",
	"sysMtaExtensionsGet", "sysMtaHookGet", "sysMtaHookQuery", "sysMtaInboundSessionGet",
	"sysMtaInboundThrottleGet", "sysMtaInboundThrottleQuery", "sysMtaMilterGet", "sysMtaMilterQuery",
	"sysMtaOutboundStrategyGet", "sysMtaOutboundThrottleGet", "sysMtaOutboundThrottleQuery",
	"sysMtaQueueQuotaGet", "sysMtaQueueQuotaQuery", "sysMtaRouteGet", "sysMtaRouteQuery", "sysMtaStageAuthGet",
	"sysMtaStageConnectGet", "sysMtaStageDataGet", "sysMtaStageEhloGet", "sysMtaStageMailGet",
	"sysMtaStageRcptGet", "sysMtaStsGet", "sysMtaTlsStrategyGet", "sysMtaTlsStrategyQuery",
	"sysMtaVirtualQueueGet", "sysMtaVirtualQueueQuery", "sysNetworkListenerGet", "sysNetworkListenerQuery",
	"sysOAuthClientGet", "sysOAuthClientQuery", "sysOidcProviderGet", "sysPublicKeyGet", "sysPublicKeyQuery",
	"sysReportSettingsGet", "sysRoleGet", "sysRoleQuery", "sysSearchGet", "sysSearchStoreGet",
	"sysSecurityGet", "sysSenderAuthGet", "sysSharingGet", "sysSieveSystemInterpreterGet",
	"sysSieveSystemScriptGet", "sysSieveSystemScriptQuery", "sysSieveUserInterpreterGet",
	"sysSmimeTrustAnchorGet", "sysSmimeTrustAnchorQuery", "sysSpamAiGet", "sysSpamClassifierGet",
	"sysSpamDnsblServerGet", "sysSpamDnsblServerQuery", "sysSpamDnsblSettingsGet", "sysSpamFileExtensionGet",
	"sysSpamFileExtensionQuery", "sysSpamPyzorGet", "sysSpamRuleGet", "sysSpamRuleQuery", "sysSpamSettingsGet",
	"sysSpamTagGet", "sysSpamTagQuery", "sysSpfReportSettingsGet", "sysStoreLookupGet", "sysStoreLookupQuery",
	"sysSystemSettingsGet", "sysTaskGet", "sysTaskQuery", "sysTaskManagerGet", "sysTenantGet",
	"sysTenantQuery", "sysTlsReportSettingsGet", "sysTracerGet", "sysTracerQuery", "sysTracingStoreGet",
	"sysWebDavGet", "sysWebHookGet", "sysWebHookQuery",
}

// ViewerDenied are the management objects whose reads the viewer never
// gets: credentials and their metadata (AccountPassword, ApiKey,
// AppPassword, Passkey, OAuthGrant, Bootstrap, SymmetricKey, Enterprise),
// people's data (SpamTrainingSample, ArchivedItem, MaskedEmail,
// SieveUserScript), messages and their envelopes (QueuedMessage, the
// queue; the received and sent DMARC, TLS and ARF reports, which carry
// senders, recipients, headers or whole messages) and the server's logs
// and traces (Log, Trace). The admin view's proxy refuses their methods
// too (ViewerDeniedObject).
var ViewerDenied = []string{"AccountPassword", "ApiKey", "AppPassword", "Passkey", "OAuthGrant", "Bootstrap", "SymmetricKey",
	"Enterprise", "SpamTrainingSample", "ArchivedItem", "MaskedEmail", "SieveUserScript",
	"QueuedMessage", "ArfExternalReport", "DmarcExternalReport", "DmarcInternalReport", "TlsExternalReport", "TlsInternalReport",
	"Log", "Trace"}

// ViewerDeniedObject reports a JMAP method's object (x:<Object>/…) that
// the viewer may never read: ViewerDenied's, and anything whose name says
// it holds messages, reports, envelopes or credentials (a later schema's
// new kin is refused before it is judged).
func ViewerDeniedObject(method string) bool {
	mgmt := strings.HasPrefix(method, "x:")
	obj, _, _ := strings.Cut(strings.TrimPrefix(method, "x:"), "/")
	for _, d := range ViewerDenied {
		if strings.EqualFold(obj, d) {
			return true
		}
	}
	lo := strings.ToLower(obj)
	for _, w := range []string{"message", "report", "envelope", "queue", "email", "mailbox", "blob", "password", "apikey", "secret", "key", "token", "credential", "log", "trace", "sample", "archived"} {
		if strings.Contains(lo, w) && !(mgmt && viewerAllowedKin[obj]) {
			return true
		}
	}
	return false
}

// viewerAllowedKin are management objects (x:) whose names match
// ViewerDeniedObject's words but hold settings only (no message, report
// or secret value).
var viewerAllowedKin = map[string]bool{
	"DkimReportSettings": true, "DmarcReportSettings": true, "DsnReportSettings": true, "SpfReportSettings": true,
	"TlsReportSettings": true, "ReportSettings": true, "MtaQueueQuota": true, "MtaVirtualQueue": true, "Email": true,
	"MemoryLookupKey": true, "MemoryLookupKeyValue": true, "ExternalPublicKey": true, "PublicKey": true, "IndexQueueStatus": true,
	"BlobStore": true, "MtaStageMail": true, "Tracer": true,
}

func init() {
	for _, l := range [][]string{MailPasswordPermissions, ExportPermissions, MailctlRolePermissions, ViewerRolePermissions} {
		for _, p := range l {
			Used = append(Used, Use{Enum: "Permission", Value: p})
		}
	}
}
