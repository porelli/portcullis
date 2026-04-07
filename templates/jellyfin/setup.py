#!/usr/bin/env python3
"""Jellyfin auto-setup: wizard, SSO plugin, branding, OIDC config."""

import os
import sys
import time
import requests

JF = "http://jellyfin:8096"
ADMIN_PASS = os.environ.get("JELLYFIN_ADMIN_PASSWORD", "changeme")
OIDC_SECRET = os.environ.get("JELLYFIN_OIDC_SECRET", "")
DOMAIN = os.environ.get("PORTCULLIS_DOMAIN", "portcullis.local")


def wait_for(url, label="Jellyfin", timeout=120):
    print(f"setup: Waiting for {label}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code < 500:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(3)
    print(f"setup: Timeout waiting for {label}")
    return False


def is_configured():
    try:
        r = requests.get(f"{JF}/System/Info/Public", timeout=5)
        return r.json().get("StartupWizardCompleted", False)
    except Exception:
        return False


def run_wizard():
    print("setup: Running startup wizard...")

    r = requests.post(f"{JF}/Startup/Configuration", json={
        "UICulture": "en-US",
        "MetadataCountryCode": "US",
        "PreferredMetadataLanguage": "en"
    })
    print(f"setup: Configuration: {r.status_code}")

    # Wait for Jellyfin to create initial user after configuration
    for i in range(20):
        try:
            r = requests.get(f"{JF}/Startup/User", timeout=5)
            if r.status_code == 200:
                print(f"setup: Initial user ready: {r.json()}")
                break
        except Exception:
            pass
        time.sleep(2)

    r = requests.post(f"{JF}/Startup/User", json={
        "Name": "admin",
        "Password": ADMIN_PASS
    })
    print(f"setup: User: {r.status_code}")

    r = requests.post(f"{JF}/Startup/RemoteAccess", json={
        "EnableRemoteAccess": True,
        "EnableAutomaticPortMapping": False
    })
    print(f"setup: RemoteAccess: {r.status_code}")

    r = requests.post(f"{JF}/Startup/Complete")
    print(f"setup: Complete: {r.status_code}")

    time.sleep(5)
    wait_for(f"{JF}/System/Info/Public", "Jellyfin post-wizard")


def authenticate():
    auth_header = 'MediaBrowser Client="Portcullis", Device="Setup", DeviceId="portcullis-setup", Version="1.0"'
    headers = {
        "Content-Type": "application/json",
        "X-Emby-Authorization": auth_header
    }

    # Try with configured password
    for pw in [ADMIN_PASS, ""]:
        try:
            r = requests.post(f"{JF}/Users/AuthenticateByName",
                              headers=headers,
                              json={"Username": "admin", "Pw": pw})
            if r.status_code == 200:
                token = r.json().get("AccessToken", "")
                if token:
                    label = "configured password" if pw == ADMIN_PASS else "empty password"
                    print(f"setup: Authenticated with {label}.")
                    return token
        except Exception as e:
            print(f"setup: Auth error: {e}")

    print("setup: Authentication failed.")
    return None


def setup_sso_plugin(token):
    auth = {"X-Emby-Authorization": f'MediaBrowser Token="{token}"'}

    # Add SSO repository
    try:
        repos = requests.get(f"{JF}/Repositories", headers=auth).json()
    except Exception:
        repos = []

    sso_repo = {
        "Name": "Jellyfin SSO",
        "Url": "https://raw.githubusercontent.com/9p4/jellyfin-plugin-sso/manifest-release/manifest.json",
        "Enabled": True
    }
    if not any(r.get("Name") == "Jellyfin SSO" for r in repos):
        repos.append(sso_repo)
    requests.post(f"{JF}/Repositories", headers={**auth, "Content-Type": "application/json"}, json=repos)
    print("setup: SSO repo added.")

    # Find and install SSO plugin
    time.sleep(3)
    try:
        packages = requests.get(f"{JF}/Packages", headers=auth).json()
    except Exception:
        packages = []

    sso_info = None
    for p in packages:
        if "SSO" in p.get("name", ""):
            vs = p.get("versions", [])
            if vs:
                sso_info = {
                    "name": p["name"],
                    "guid": p.get("guid", ""),
                    "version": vs[0].get("version") or vs[0].get("versionStr")
                }
            break

    if sso_info:
        r = requests.post(
            f"{JF}/Packages/Installed/{requests.utils.quote(sso_info['name'])}",
            headers=auth,
            params={
                "assemblyGuid": sso_info["guid"],
                "version": sso_info["version"],
                "repositoryUrl": "https://raw.githubusercontent.com/9p4/jellyfin-plugin-sso/manifest-release/manifest.json"
            }
        )
        print(f"setup: Plugin '{sso_info['name']}' {sso_info['version']} install: {r.status_code}")

        # Wait for the async download to complete (plugin is ~100KB)
        print("setup: Waiting for plugin download...")
        time.sleep(15)
    else:
        print("setup: SSO plugin not found in catalog.")
        return False

    # Set branding
    requests.post(f"{JF}/System/Configuration/branding",
                  headers={**auth, "Content-Type": "application/json"},
                  json={
                      "LoginDisclaimer": '<form action="/sso/OID/start/keycloak"><button class="raised block emby-button button-submit">Sign in with SSO</button></form>',
                      "CustomCss": ""
                  })
    print("setup: Branding set.")
    return True


def configure_sso(token):
    auth = {"X-Emby-Authorization": f'MediaBrowser Token="{token}"'}

    # Find SSO plugin ID
    sso_plugin_id = None
    try:
        plugins = requests.get(f"{JF}/Plugins", headers=auth).json()
        for p in plugins:
            if "SSO" in p.get("Name", ""):
                sso_plugin_id = p["Id"]
                break
    except Exception:
        pass

    if not sso_plugin_id:
        print("setup: SSO plugin not found in installed plugins.")
        return

    # Format GUID with dashes for API
    guid = sso_plugin_id
    if "-" not in guid:
        guid = f"{guid[:8]}-{guid[8:12]}-{guid[12:16]}-{guid[16:20]}-{guid[20:]}"

    sso_config = {
        "SamlConfigs": {},
        "OidConfigs": {
            "keycloak": {
                "OidEndpoint": f"https://auth.{DOMAIN}/realms/portcullis/.well-known/openid-configuration",
                "OidClientId": "jellyfin",
                "OidSecret": OIDC_SECRET,
                "Enabled": True,
                "EnableAuthorization": True,
                "EnableAllFolders": True,
                "EnabledFolders": [],
                "AdminRoles": ["admin_jellyfin"],
                "Roles": ["users_jellyfin", "admin_jellyfin"],
                "EnableFolderRoles": False,
                "OidScopes": ["openid", "profile", "groups"],
                "RoleClaim": "groups",
                "DisableHttps": False,
                "DisablePushedAuthorization": True,
                "DoNotValidateEndpoints": False
            }
        }
    }

    r = requests.post(f"{JF}/Plugins/{guid}/Configuration",
                      headers={**auth, "Content-Type": "application/json"},
                      json=sso_config)
    print(f"setup: SSO config via plugin API: {r.status_code}")


def configure_network(token):
    """Set KnownProxies so Jellyfin trusts X-Forwarded-Proto from Traefik."""
    auth = {"X-Emby-Authorization": f'MediaBrowser Token="{token}"'}

    try:
        net = requests.get(f"{JF}/System/Configuration/network", headers=auth).json()
    except Exception:
        print("setup: Could not read network config.")
        return

    net["KnownProxies"] = ["172.16.0.0/12", "10.0.0.0/8"]
    r = requests.post(f"{JF}/System/Configuration/network",
                      headers={**auth, "Content-Type": "application/json"},
                      json=net)
    print(f"setup: Network config (KnownProxies): {r.status_code}")


def main():
    if not wait_for(f"{JF}/Startup/Configuration"):
        sys.exit(1)

    if is_configured():
        print("setup: Already configured, skipping wizard.")
    else:
        run_wizard()

    token = authenticate()
    if not token:
        print("setup: Cannot proceed without auth. Manual setup needed.")
        sys.exit(0)

    if not setup_sso_plugin(token):
        print("setup: SSO plugin setup failed. Done.")
        sys.exit(0)

    # Restart to load plugin
    auth = {"X-Emby-Authorization": f'MediaBrowser Token="{token}"'}
    requests.post(f"{JF}/System/Restart", headers=auth)
    print("setup: Restarting Jellyfin to load SSO plugin...")
    time.sleep(10)
    wait_for(f"{JF}/System/Info/Public", "Jellyfin post-restart")

    # Re-authenticate
    token = authenticate()
    if token:
        configure_sso(token)
        configure_network(token)
    else:
        print("setup: Re-auth failed. SSO config skipped.")

    print("setup: Done!")


if __name__ == "__main__":
    main()
