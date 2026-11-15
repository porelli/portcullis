package stalwart

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
		"sysQueuedMessageGet", "sysQueuedMessageQuery",
		"sysActionCreate", "actionReloadSettings", "actionReloadTlsCertificates", "actionInvalidateCaches", "actionReloadLookupStores",
		"sysDmarcExternalReportGet", "sysDmarcExternalReportQuery", "sysTlsExternalReportGet", "sysTlsExternalReportQuery",
		"sysSpamSettingsGet", "sysSpamSettingsUpdate",
		"sysMemoryLookupKeyGet", "sysMemoryLookupKeyCreate", "sysMemoryLookupKeyUpdate", "sysMemoryLookupKeyDestroy", "sysMemoryLookupKeyQuery",
		// Settings mailctl edits after the bootstrap: the spam rules'
		// external lookups (kept disabled), the DNSBL servers and sender
		// authentication (the Hub's DNSBL switches, degraded mode M9).
		"sysHttpLookupGet", "sysHttpLookupQuery", "sysHttpLookupUpdate",
		"sysSpamDnsblServerGet", "sysSpamDnsblServerQuery", "sysSpamDnsblServerUpdate",
		"sysSenderAuthGet", "sysSenderAuthUpdate",
		// The per-account limits (MtaInboundThrottle) and, with
		// MAIL_SUBMISSION_LAN_ONLY, the SASL rule (MtaStageAuth).
		"sysMtaInboundThrottleGet", "sysMtaInboundThrottleCreate", "sysMtaInboundThrottleUpdate",
		"sysMtaInboundThrottleDestroy", "sysMtaInboundThrottleQuery",
		"sysMtaStageAuthGet", "sysMtaStageAuthUpdate",
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

func init() {
	for _, l := range [][]string{MailPasswordPermissions, ExportPermissions, MailctlRolePermissions} {
		for _, p := range l {
			Used = append(Used, Use{Enum: "Permission", Value: p})
		}
	}
}
