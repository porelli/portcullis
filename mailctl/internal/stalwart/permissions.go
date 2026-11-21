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
	"sysAddressBookGet", "sysAlertGet", "sysAlertQuery", "sysAllowedIpGet", "sysAllowedIpQuery",
	"sysApplicationGet", "sysApplicationQuery", "sysAuthenticationGet", "sysBlockedIpGet", "sysBlockedIpQuery",
	"sysCalendarGet", "sysCalendarAlarmGet", "sysCalendarSchedulingGet", "sysCertificateGet",
	"sysCertificateQuery", "sysClusterNodeGet", "sysClusterNodeQuery", "sysClusterRoleGet",
	"sysClusterRoleQuery", "sysDataRetentionGet", "sysDkimReportSettingsGet", "sysDkimSignatureGet",
	"sysDkimSignatureQuery", "sysDmarcReportSettingsGet", "sysDnsResolverGet", "sysDomainGet",
	"sysDomainQuery", "sysDsnReportSettingsGet", "sysEmailGet", "sysEncryptionGet", "sysEventTracingLevelGet",
	"sysEventTracingLevelQuery", "sysExternalPublicKeyGet", "sysExternalPublicKeyQuery", "sysFileStorageGet",
	"sysHttpFormGet", "sysImapGet", "sysIndexQueueStatusGet", "sysIndexQueueStatusQuery", "sysJmapGet",
	"sysMailingListGet", "sysMailingListQuery", "sysMemoryLookupKeyGet", "sysMemoryLookupKeyQuery",
	"sysMemoryLookupKeyValueGet", "sysMemoryLookupKeyValueQuery", "sysMetadataGet", "sysMetricGet",
	"sysMetricQuery", "sysMtaConnectionStrategyGet", "sysMtaConnectionStrategyQuery",
	"sysMtaDeliveryScheduleGet", "sysMtaDeliveryScheduleQuery", "sysMtaExtensionsGet",
	"sysMtaInboundSessionGet", "sysMtaInboundThrottleGet", "sysMtaInboundThrottleQuery", "sysMtaMilterGet",
	"sysMtaMilterQuery", "sysMtaOutboundStrategyGet", "sysMtaOutboundThrottleGet",
	"sysMtaOutboundThrottleQuery", "sysMtaQueueQuotaGet", "sysMtaQueueQuotaQuery", "sysMtaRouteGet",
	"sysMtaRouteQuery", "sysMtaStageAuthGet", "sysMtaStageConnectGet", "sysMtaStageDataGet",
	"sysMtaStageEhloGet", "sysMtaStageMailGet", "sysMtaStageRcptGet", "sysMtaStsGet", "sysMtaTlsStrategyGet",
	"sysMtaTlsStrategyQuery", "sysMtaVirtualQueueGet", "sysMtaVirtualQueueQuery", "sysNetworkListenerGet",
	"sysNetworkListenerQuery", "sysOAuthClientGet", "sysOAuthClientQuery", "sysOidcProviderGet",
	"sysPublicKeyGet", "sysPublicKeyQuery", "sysReportSettingsGet", "sysRoleGet", "sysRoleQuery",
	"sysSearchGet", "sysSecurityGet", "sysSenderAuthGet", "sysSharingGet", "sysSieveSystemInterpreterGet",
	"sysSieveSystemScriptGet", "sysSieveSystemScriptQuery", "sysSieveUserInterpreterGet",
	"sysSmimeTrustAnchorGet", "sysSmimeTrustAnchorQuery", "sysSpamClassifierGet", "sysSpamFileExtensionGet",
	"sysSpamFileExtensionQuery", "sysSpamPyzorGet", "sysSpamRuleGet", "sysSpamRuleQuery", "sysSpamSettingsGet",
	"sysSpamTagGet", "sysSpamTagQuery", "sysSpfReportSettingsGet", "sysSystemSettingsGet", "sysTaskGet",
	"sysTaskQuery", "sysTaskManagerGet", "sysTenantGet", "sysTenantQuery", "sysTlsReportSettingsGet",
	"sysWebDavGet",
}

// ViewerDenied are the management objects whose reads the viewer never
// gets (contract §19.13):
//   - credentials and their metadata: AccountPassword, ApiKey,
//     AppPassword, Passkey, OAuthGrant, Bootstrap, SymmetricKey, Enterprise;
//   - people's data: SpamTrainingSample, ArchivedItem, MaskedEmail,
//     SieveUserScript;
//   - messages and their envelopes: QueuedMessage (the queue) and the
//     received and sent DMARC, TLS and ARF reports;
//   - every object whose plain (unmasked) fields can hold a secret: a
//     connection URL or username, HTTP headers, a DNS or HTTP provider's
//     keys, a lookup zone (the Spamhaus DQS key sits in SpamDnsblServer's
//     zone): the stores, directories, DNS servers, hooks, tracers,
//     metrics exporters, AI models, HTTP lookups and the DNSBL settings;
//   - the server's logs and traces: Log, Trace.
//
// TestViewerSecretFreeFields walks the schema snapshot so a field that
// could hold a secret can't come back unjudged.
var ViewerDenied = []string{"AccountPassword", "ApiKey", "AppPassword", "Passkey", "OAuthGrant", "Bootstrap", "SymmetricKey",
	"Enterprise", "SpamTrainingSample", "ArchivedItem", "MaskedEmail", "SieveUserScript",
	"QueuedMessage", "ArfExternalReport", "DmarcExternalReport", "DmarcInternalReport", "TlsExternalReport", "TlsInternalReport",
	"SpamDnsblServer", "SpamDnsblSettings", "AiModel", "SpamAi", "Asn", "BlobStore", "Cache", "Coordinator", "DataStore", "Directory",
	"DnsServer", "Http", "HttpLookup", "InMemoryStore", "Metrics", "MetricsStore", "MtaHook", "SearchStore", "StoreLookup",
	"Tracer", "TracingStore", "WebHook",
	"Log", "Trace"}

// viewerMethods are the only JMAP methods the admin view forwards: x:<Obj>/get
// and x:<Obj>/query for exactly the objects ViewerRolePermissions reads
// (one list for both layers, contract §19.13).
var viewerMethods = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range ViewerRolePermissions {
		if obj, ok := strings.CutSuffix(strings.TrimPrefix(p, "sys"), "Get"); ok && p != obj {
			m["x:"+obj+"/get"] = true
		} else if obj, ok := strings.CutSuffix(strings.TrimPrefix(p, "sys"), "Query"); ok {
			m["x:"+obj+"/query"] = true
		}
	}
	return m
}()

// ViewerMethodAllowed reports a JMAP method the admin view may forward:
// exactly x:<Obj>/get or x:<Obj>/query (lowercase x:, exact case) of an
// object the viewer's role reads. Everything else is refused.
func ViewerMethodAllowed(method string) bool { return viewerMethods[method] }

func init() {
	for _, l := range [][]string{MailPasswordPermissions, ExportPermissions, MailctlRolePermissions, ViewerRolePermissions} {
		for _, p := range l {
			Used = append(Used, Use{Enum: "Permission", Value: p})
		}
	}
}
