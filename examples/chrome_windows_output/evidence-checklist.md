# STIGPilot Evidence Checklist

Source: `new.xml`
Controls included: 46

## Endpoint/Windows Admin

### V-221558 - Firewall traversal from remote host must be disabled.

- Severity: medium
- Rule ID: SV-221558r960804_rule
- Tags: IAM, Remote Access, Network Security, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If RemoteAccessHostFirewallTraversal is not displayed under the Policy Name column or it is not set to false under the Policy Value column, the...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] Network device configuration excerpt or management console export
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221559 - Site tracking users location must be disabled.

- Severity: medium
- Rule ID: SV-221559r961083_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If DefaultGeolocationSetting is not displayed under the Policy Name column or it is not set to 2, then this is a finding. Windows method: 1. St...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221561 - Sites ability to show pop-ups must be disabled.

- Severity: medium
- Rule ID: SV-221561r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If DefaultPopupsSetting is not displayed under the Policy Name column or it is not set to 2, then this is a finding. Windows method: 1. Start r...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221562 - Extensions installation must be blocklisted by default.

- Severity: medium
- Rule ID: SV-221562r960879_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If ExtensionInstallBlocklist is not displayed under the Policy Name column or it is not set to * under the Policy Value column, then this is a...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221563 - Extensions that are approved for use must be allowlisted.

- Severity: low
- Rule ID: SV-221563r1015468_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If ExtensionInstallAllowlist is not displayed under the Policy Name column or it is not set to oiigbmnaadbkfbmpbfijlflahbdbdgdf or a list of ad...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221564 - The default search providers name must be set.

- Severity: medium
- Rule ID: SV-221564r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If DefaultSearchProviderName is displayed under the Policy Name column or it is not set to an organization approved encrypted search provider t...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221565 - The default search provider URL must be set to perform encrypted searches.

- Severity: medium
- Rule ID: SV-221565r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: If the system is on the SIPRNet, this requirement is NA. Universal method: 1. In the omnibox (address bar) type chrome://policy. 2. If DefaultSearchProviderSearchURL is not displayed under the Policy Name column or it...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221566 - Default search provider must be enabled.

- Severity: medium
- Rule ID: SV-221566r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If DefaultSearchProviderEnabled is not displayed under the Policy Name column or it is not set to true under the Policy Value column, then this...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221567 - The Password Manager must be disabled.

- Severity: medium
- Rule ID: SV-221567r960963_rule
- Tags: IAM, Audit Logging, Password Policy, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If PasswordManagerEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221570 - Background processing must be disabled.

- Severity: medium
- Rule ID: SV-221570r960921_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If BackgroundModeEnabled is not displayed under the Policy Name column and it is not set to false under the Policy Value column, then this is a...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221571 - Google Data Synchronization must be disabled.

- Severity: medium
- Rule ID: SV-221571r987620_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If SyncDisabled is not displayed under the Policy Name column or it is not set to true under the Policy Value column, then this is a finding. W...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221572 - The URL protocol schema javascript must be disabled.

- Severity: medium
- Rule ID: SV-221572r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy. 2. If URLBlocklist is not displayed under the Policy Name column or it is not set to javascript://* under the Policy Value column, this is a find...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221573 - Cloud print sharing must be disabled.

- Severity: medium
- Rule ID: SV-221573r987620_rule
- Tags: IAM, Windows, GPO, Registry, Cloud, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If CloudPrintProxyEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] Cloud policy, role, or configuration export
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221574 - Network prediction must be disabled.

- Severity: medium
- Rule ID: SV-221574r961863_rule
- Tags: IAM, Network Security, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If "NetworkPredictionOptions" is not displayed under the “Policy Name” column or it is not set to "2" under the “Policy Value” column, this is...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] Network device configuration excerpt or management console export
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221575 - Metrics reporting to Google must be disabled.

- Severity: medium
- Rule ID: SV-221575r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If MetricsReportingEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221576 - Search suggestions must be disabled.

- Severity: medium
- Rule ID: SV-221576r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If SearchSuggestEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a f...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221577 - Importing of saved passwords must be disabled.

- Severity: medium
- Rule ID: SV-221577r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If ImportSavedPasswords is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a f...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221578 - Incognito mode must be disabled.

- Severity: medium
- Rule ID: SV-221578r960864_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If IncognitoModeAvailability is not displayed under the Policy Name column or it is not set to 1 under the Policy Value column, then this is a...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221579 - Online revocation checks must be performed.

- Severity: medium
- Rule ID: SV-221579r961893_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If EnableOnlineRevocationChecks is not displayed under the Policy Name column or it is not set to true under the Policy Value column, then this...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221580 - Safe Browsing must be enabled.

- Severity: medium
- Rule ID: SV-221580r961083_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If SafeBrowsingProtectionLevel is not displayed under the Policy Name column or it is not set to 1 or 2 under the Policy Value column, then thi...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221581 - Browser history must be saved.

- Severity: medium
- Rule ID: SV-221581r961128_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If the policy 'SavingBrowserHistoryDisabled' is not shown or is not set to false, then this is a finding. Windows method: 1. Start regedit 2. N...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221584 - The version of Google Chrome running on the system must be a supported version.

- Severity: medium
- Rule ID: SV-221584r961683_rule
- Tags: Windows, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://settings/help 2. Cross-reference the build information displayed with the Google Chrome site to identify, at minimum, the oldest supported build availabl...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221586 - Deletion of browser history must be disabled.

- Severity: medium
- Rule ID: SV-221586r960879_rule
- Tags: IAM, Windows, GPO, Registry, Defender/AV, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If the policy "AllowDeletingBrowserHistory" is not shown or is not set to false, this is a finding. Windows method: 1. Start regedit 2. Navigat...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221587 - Prompt for download location must be enabled.

- Severity: medium
- Rule ID: SV-221587r960879_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome:// policy 2. If "PromptForDownloadLocation" is not displayed under the "Policy Name" column or it is not set to "true" under the "Policy Value" column, the...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221588 - Download restrictions must be configured.

- Severity: medium
- Rule ID: SV-221588r1106670_rule
- Tags: IAM, Endpoint Security, Windows, GPO, Registry, Browser Security
- Check summary: If the system is on the SIPRNet, this requirement is Not Applicable. Universal method: 1. In the omnibox (address bar) type "chrome:// policy". 2. If "DownloadRestrictions" is not displayed under the "Policy Name" col...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221590 - Safe Browsing Extended Reporting must be disabled.

- Severity: medium
- Rule ID: SV-221590r961083_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If "SafeBrowsingExtendedReportingEnabled" is not displayed under the "Policy Name" column or it is not set to "False", this is a finding. Windo...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221591 - WebUSB must be disabled.

- Severity: medium
- Rule ID: SV-221591r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If "DefaultWebUsbGuardSetting" is not displayed under the "Policy Name" column or it is not set to "2", this is a finding. Windows method: 1. S...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221594 - Google Cast must be disabled.

- Severity: medium
- Rule ID: SV-221594r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If "EnableMediaRouter" is not displayed under the "Policy Name" column or it is not set to "False", this is a finding. Windows method: 1. Start...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] Network device configuration excerpt or management console export
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221595 - Autoplay must be disabled.

- Severity: medium
- Rule ID: SV-221595r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If "AutoplayAllowed" is not displayed under the "Policy Name" column or it is not set to "False", this is a finding. Windows method: 1. Start r...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221596 - URLs must be allowlisted for Autoplay use.

- Severity: medium
- Rule ID: SV-221596r961092_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar), type chrome://policy. 2. If “AutoplayAllowlist” under the “Policy Name” column may be set to a list of administrator-approved URLs under the “Policy Value” column. Th...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221597 - Anonymized data collection must be disabled.

- Severity: medium
- Rule ID: SV-221597r961083_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If "UrlKeyedAnonymizedDataCollectionEnabled" is not displayed under the “Policy Name” column or it is not set to "0" under the “Policy Value” c...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221598 - Collection of WebRTC event logs must be disabled.

- Severity: medium
- Rule ID: SV-221598r961083_rule
- Tags: IAM, Network Security, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If "WebRtcEventLogCollectionAllowed" is not displayed under the “Policy Name” column or it is not set to "0" under the “Policy Value” column, t...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-221599 - Chrome development tools must be disabled.

- Severity: low
- Rule ID: SV-221599r961167_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If the policy "DeveloperToolsAvailability" is not shown or is not set to "2", this is a finding. Windows method: 1. Start regedit 2. Navigate t...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-226401 - Guest Mode must be disabled.

- Severity: medium
- Rule ID: SV-226401r961083_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If BrowserGuestModeEnabled is not displayed under the Policy Name column or it is not set to 0 under the Policy Value column, this is a finding...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-226402 - AutoFill for credit cards must be disabled.

- Severity: medium
- Rule ID: SV-226402r961083_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If AutofillCreditCardEnabled is not displayed under the Policy Name column or it is not set to 0 under the Policy Value column, this is a findi...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-226403 - AutoFill for addresses must be disabled.

- Severity: medium
- Rule ID: SV-226403r961083_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If AutofillAddressEnabled is not displayed under the Policy Name column or it is not set to 0 under the Policy Value column, this is a finding....

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-226404 - Import AutoFill form data must be disabled.

- Severity: medium
- Rule ID: SV-226404r961083_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If ImportAutofillFormData is not displayed under the Policy Name column or it is not set to 0 under the Policy Value column, this is a finding....

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-241787 - Web Bluetooth API must be disabled.

- Severity: medium
- Rule ID: SV-241787r960963_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If DefaultWebBluetoothGuardSetting is not displayed under the Policy Name column or it is not set to 2 under the Policy Value column, then this...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-245538 - Use of the QUIC protocol must be disabled.

- Severity: medium
- Rule ID: SV-245538r961470_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar), type chrome://policy. 2. If QuicAllowed is not displayed under the Policy Name column or it is not set to False under the Policy Value column, this is a finding. Wind...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-245539 - Session only based cookies must be enabled.

- Severity: medium
- Rule ID: SV-245539r960864_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar), type chrome://policy 2. If the policy "DefaultCookiesSetting" is not shown or is not set to "4", this is a finding. Windows method: 1. Start regedit. 2. Navigate to H...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-275780 - Create Themes with AI must be disabled.

- Severity: medium
- Rule ID: SV-275780r1106603_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type "chrome:// policy". 2. If "CreateThemesSettings" is not displayed under the "Policy Name" column or it is not set to "2" under the "Policy Value" column, this is...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-275781 - DevTools Generative AI features must be disabled.

- Severity: medium
- Rule ID: SV-275781r1106671_rule
- Tags: IAM, Endpoint Security, Network Security, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type "chrome:// policy". 2. If "DevToolsGenAiSettings" is not displayed under the "Policy Name" column or it is not set to "2" under the "Policy Value" column, this is...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-275782 - GenAI local foundational model must be disabled.

- Severity: medium
- Rule ID: SV-275782r1106672_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type "chrome:// policy". 2. If "GenAILocalFoundationalModelSettings" is not displayed under the "Policy Name" column or it is not set to "1" under the "Policy Value" c...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-275783 - Help Me Write must be disabled.

- Severity: medium
- Rule ID: SV-275783r1106612_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type "chrome:// policy". 2. If "HelpMeWriteSettings" is not displayed under the "Policy Name" column or it is not set to "2" under the "Policy Value" column, this is a...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-275784 - AI-powered History Search must be disabled.

- Severity: medium
- Rule ID: SV-275784r1106615_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type "chrome:// policy". 2. If "HistorySearchSettings" is not displayed under the "Policy Name" column or it is not set to "2" under the "Policy Value" column, this is...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-275785 - Tab Compare Settings must be disabled.

- Severity: medium
- Rule ID: SV-275785r1106673_rule
- Tags: IAM, Windows, GPO, Registry, Browser Security
- Check summary: Universal method: 1. In the omnibox (address bar) type "chrome:// policy". 2. If "TabCompareSettings" is not displayed under the "Policy Name" column or it is not set to "2" under the "Policy Value" column, this is a...

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes
