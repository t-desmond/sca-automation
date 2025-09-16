#!/bin/bash

# Set shell options based on shell type
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Script metadata
readonly SCRIPT_NAME="wazuh-sca-automation.sh"
readonly SCRIPT_VERSION="1.0.0"

# Default configuration
LOG_LEVEL=${LOG_LEVEL:-INFO}
FIXES_APPLIED=0
TESTS_PASSED=0
TESTS_FAILED=0

# Arrays to store check results
FAILED_CHECKS=""
PASSED_CHECKS=""

# Arrays for OS-specific checks
MACOS_CHECKS="35001_macos 35003_macos 35004_macos 35026_macos 35029_macos 35030_macos 35036_macos 35037_macos 35039_macos 35040_macos 35042_macos"
LINUX_CHECKS="28500_linux 28523_linux 28526_linux 28528_linux 28552_linux 28553_linux 28566_linux 28570_linux 28574_linux 28575_linux 28576_linux 28590_linux 28591_linux 28592_linux 28593_linux 28597_linux 28598_linux 28599_linux 28601_linux 28602_linux 28603_linux 28605_linux 28611_linux 28613_linux 28617_linux 28618_linux 28623_linux 28626_linux 28627_linux 28632_linux 28634_linux 28635_linux 28638_linux 28645_linux 28647_linux 28648_linux 28649_linux 28650_linux 28652_linux 28653_linux 28660_linux 28661_linux 28664_linux"

# Arrays of checks not implemented(couldn't be automated/conflicting with other checks)
NOT_IMPLEMENTED_LINUX_CHECKS="28587_linux 28600_linux 28604_linux"
NOT_IMPLEMENTED_MACOS_CHECKS=""

# Determine OS-specific paths and settings
case "$(uname)" in
    "Linux") 
        OS_TYPE="linux"
        CHECKS="$LINUX_CHECKS"
        ;;
    "Darwin") 
        OS_TYPE="macos"
        CHECKS="$MACOS_CHECKS"
        ;;
    *) 
        echo "Error: Unsupported operating system: $(uname)"
        exit 1
        ;;
esac

# Define text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

#######################################
# Logging functions
#######################################

# Function for logging with timestamp
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    case "${LOG_LEVEL}" in
        "DEBUG") ;;
        "INFO")  
            [ "$LEVEL" = "DEBUG" ] && return 0
            [ "$LEVEL" = "STEP" ] && return 0
            ;;
        "WARNING") 
            [ "$LEVEL" = "WARNING" ] || [ "$LEVEL" = "ERROR" ] || return 0 
            ;;
        "ERROR") 
            [ "$LEVEL" = "ERROR" ] || return 0 
            ;;
    esac
    
    local COLORED_LEVEL
    case "$LEVEL" in
        "INFO") COLORED_LEVEL="${BLUE}${BOLD}[INFO]${NORMAL}" ;;
        "WARNING") COLORED_LEVEL="${YELLOW}${BOLD}[WARNING]${NORMAL}" ;;
        "ERROR") COLORED_LEVEL="${RED}${BOLD}[ERROR]${NORMAL}" ;;
        "SUCCESS") COLORED_LEVEL="${GREEN}${BOLD}[SUCCESS]${NORMAL}" ;;
        "DEBUG") COLORED_LEVEL="${BLUE}[DEBUG]${NORMAL}" ;;
        "STEP") COLORED_LEVEL="${BLUE}${BOLD}[STEP]${NORMAL}" ;;
    esac
    
    printf "%b\n" "${TIMESTAMP} ${COLORED_LEVEL} ${MESSAGE}"
}

# Logging helpers
info_message() {
    log "INFO" "$*"
}

warn_message() {
    log "WARNING" "$*"
}

error_message() {
    log "ERROR" "$*"
}

success_message() {
    log "SUCCESS" "$*"
}

debug_message() {
    log "DEBUG" "$*"
}

print_step() {
    log "STEP" "$1: $2"
}

#######################################
# Utility functions
#######################################

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Ensure root privileges, either directly or through sudo
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        if command_exists sudo; then
            sudo "$@"
        else
            error_message "This script requires root privileges. Please run with sudo or as root."
            return 1
        fi
    else
        "$@"
    fi
}

#######################################
# MacOS SCA Check Functions
#######################################

# 35001: Ensure Automatic Software Updates Is Enabled
check_rule_35001_macos() {
    info_message "Checking rule 35001_macos: Enable Automatic Software Updates on macOS"

    debug_message "Querying com.apple.SoftwareUpdate:AutomaticDownload"
    local setting
    setting=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('AutomaticDownload')")

    debug_message "Result: AutomaticDownload = ${setting:-unset}"

    if [ "$setting" = "1" ]; then
        success_message "Automatic software updates are enabled"
        return 0
    else
        error_message "Automatic software updates are disabled"
        return 1
    fi
}


# 35003: Ensure Install Application Updates from the App Store Is Enabled
check_rule_35003_macos() {
    info_message "Checking rule 35003_macos: Enable Automatic App Store Updates on macOS"

    debug_message "Reading com.apple.commerce:AutoUpdate"
    local setting
    setting=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null || echo "unset")

    debug_message "Result: AutoUpdate = ${setting}"

    if [ "$setting" = "1" ]; then
        success_message "Automatic App Store updates are enabled"
        return 0
    else
        error_message "Automatic App Store updates are disabled"
        return 1
    fi
}

# 35004: Ensure Install Security Responses and System Files Is Enabled
check_rule_35004_macos() {
    info_message "Checking rule 35004_macos: Enable Automatic Security Updates & System Files"

    debug_message "Reading com.apple.SoftwareUpdate:ConfigDataInstall and CriticalUpdateInstall"
    local cfg critical
    cfg=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('ConfigDataInstall')" 2>/dev/null || echo "unset")
    critical=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('CriticalUpdateInstall')" 2>/dev/null || echo "unset")

    debug_message "Result: ConfigDataInstall=${cfg}, CriticalUpdateInstall=${critical}"

    if [ "$cfg" = "1" ] && [ "$critical" = "1" ]; then
        success_message "Security responses and system files updates are enabled"
        return 0
    else
        error_message "Security responses and/or system files updates are disabled"
        return 1
    fi
}

# 35026: Ensure Power Nap Is Disabled for Intel Macs
check_rule_35026_macos() {
    info_message "Checking rule 35026_macos: Disable Power Nap"

    local output
    output=$(pmset -g custom 2>/dev/null || true)

    if echo "$output" | grep -qE '\\bpowernap\\s+1\\b'; then
        error_message "Power Nap is enabled"
        return 1
    fi

    debug_message "No 'powernap 1' found; Power Nap appears disabled."
    success_message "Power Nap is disabled"
    return 0
}

# 35030: Ensure Login Window Displays as Name and Password Is Enabled
check_rule_35030_macos() {
    info_message "Checking rule 35030_macos: Login window shows name and password (SHOWFULLNAME)"

    local setting
    setting=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('SHOWFULLNAME')" 2>/dev/null || echo "unset")
    debug_message "Result: SHOWFULLNAME=${setting}"

    if [ "$setting" = "1" ] || [ "$setting" = "true" ]; then
        success_message "Login window shows name and password"
        return 0
    else
        error_message "Login window does not show name and password"
        return 1
    fi
}

# 35029: Ensure a Custom Message for the Login Screen Is Enabled
check_rule_35029_macos() {
    info_message "Checking rule 35029_macos: Login window banner message configured"
    local msg
    msg=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('LoginwindowText')" 2>/dev/null || echo "unset")
    debug_message "Result: LoginwindowText=${msg}"
    if [ -n "$msg" ] && [ "$msg" != "unset" ]; then
        success_message "Login window banner message is configured"
        return 0
    else
        error_message "Login window banner message is not configured"
        return 1
    fi
}

# 35036: Ensure Security Auditing Is Enabled (auditd)
check_rule_35036_macos() {
    info_message "Checking rule 35036_macos: macOS auditd service is enabled"
    local svc
    svc=$(maybe_sudo launchctl list 2>/dev/null | grep com.apple.auditd)
    
    if [ -n "$svc" ]; then
        success_message "macOS auditd service is enabled"
        return 0
    fi
    error_message "macOS auditd service is not enabled"
    return 1
}

# 35037: Ensure Security Auditing Flags For User-Attributable Events Are Configured
check_rule_35037_macos() {
    info_message "Checking rule 35037_macos: Audit flags configuration"
    if maybe_sudo grep -qE '^flags.*-all.*ad.*aa.*lo' /etc/security/audit_control 2>/dev/null || \
       maybe_sudo grep -qE '^flags.*-fm.*-ex.*ad.*aa.*lo.*-fr.*-fw' /etc/security/audit_control 2>/dev/null; then
        success_message "Audit flags are properly configured"
        return 0
    else
        error_message "Audit flags are not properly configured"
        return 1
    fi
}

# 35039: Ensure Security Auditing Retention Is Enabled
check_rule_35039_macos() {
    info_message "Checking rule 35039_macos: Audit log retention policy"
    local line
    line=$(maybe_sudo grep -E '^expire-after:' /etc/security/audit_control 2>/dev/null || true)
    if echo "$line" | grep -qE '^expire-after:[[:space:]]*([6-9][0-9]|[1-9][0-9]{2,})d'; then
        success_message "Audit log retention policy is properly configured"
        return 0
    elif echo "$line" | grep -qE '^expire-after:[[:space:]]*([5-9]|[1-9][0-9]+)G'; then
        success_message "Audit log retention policy is properly configured"
        return 0
    fi
    error_message "Audit log retention policy is not properly configured"
    return 1
}

# 35040: Ensure Bonjour Advertising Services Is Disabled
check_rule_35040_macos() {
    info_message "Checking rule 35040_macos: Disable Bonjour multicast advertisements"
    local setting
    setting=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder').objectForKey('NoMulticastAdvertisements')" 2>/dev/null || echo "unset")
    if [ "$setting" = "1" ]; then
        success_message "Bonjour multicast advertisements are disabled"
        return 0
    else
        error_message "Bonjour multicast advertisements are not disabled"
        return 1
    fi
}

# 35042: Ensure NFS Server Is Disabled
check_rule_35042_macos() {
    info_message "Checking rule 35042_macos: NFS server is disabled"
    local svc_exists exports_exists nfsconf_exists
    if launchctl list 2>/dev/null | grep -q com.apple.nfsd; then
        error_message "NFS server is enabled"
        return 1
    fi
    exports_exists="false"
    nfsconf_exists="false"
    [ -f /etc/exports ] && exports_exists="true"
    [ -f /etc/nfs.conf ] && nfsconf_exists="true"
    debug_message "/etc/exports exists=${exports_exists}, /etc/nfs.conf exists=${nfsconf_exists}"
    if [ "$exports_exists" = "false" ]; then
        success_message "NFS server is disabled"
        return 0
    else
        error_message "NFS server is not properly disabled"
        return 1
    fi
}

#######################################
# MacOS SCA Fix Functions
#######################################

fix_rule_35001_macos() {
    info_message "Applying fix for rule 35001_macos: Enable Automatic Software Updates on macOS"
    
    print_step 1 "Enabling automatic software updates via defaults command"
    if maybe_sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true; then
        debug_message "defaults write for com.apple.SoftwareUpdate AutomaticDownload succeeded, verifying..."
        local verify
        verify=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('AutomaticDownload')" 2>/dev/null || echo "unset")
        debug_message "Verification readback: AutomaticDownload=${verify}"
        if [ "$verify" = "1" ]; then
            success_message "Automatic software updates enabled"
            return 0
        else
            error_message "Verification failed: AutomaticDownload not set to 1"
            return 1
        fi
    else
        error_message "Failed to enable automatic software updates"
        return 1
    fi
}

# 35003: Ensure Install Application Updates from the App Store Is Enabled
fix_rule_35003_macos() {
    info_message "Applying fix for rule 35003_macos: Enable Automatic App Store Updates on macOS"

    print_step 1 "Enabling automatic App Store updates via defaults command"
    if maybe_sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool TRUE; then
        debug_message "defaults write for com.apple.commerce AutoUpdate succeeded, verifying..."
        local verify
        verify=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null || echo "unset")
        debug_message "Verification readback: AutoUpdate=${verify}"
        if [ "$verify" = "1" ]; then
            success_message "Automatic App Store updates enabled"
            return 0
        else
            error_message "Verification failed: AutoUpdate not set to 1"
            return 1
        fi
    else
        error_message "Failed to enable automatic App Store updates"
        return 1
    fi
}

# 35004: Ensure Install Security Responses and System Files Is Enabled
fix_rule_35004_macos() {
    info_message "Applying fix for rule 35004_macos: Enable Automatic Security Responses & System Files"

    print_step 1 "Enabling ConfigDataInstall and CriticalUpdateInstall"
    if maybe_sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true && \
       maybe_sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true; then
        debug_message "defaults write succeeded; verifying..."
        local cfg critical
        cfg=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('ConfigDataInstall')" 2>/dev/null || echo "unset")
        critical=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('CriticalUpdateInstall')" 2>/dev/null || echo "unset")
        debug_message "Verification readback: ConfigDataInstall=${cfg}, CriticalUpdateInstall=${critical}"
        if [ "$cfg" = "1" ] && [ "$critical" = "1" ]; then
            success_message "Security responses and system files updates enabled"
            return 0
        else
            error_message "Verification failed: expected both values to be 1"
            return 1
        fi
    else
        error_message "Failed to set ConfigDataInstall/CriticalUpdateInstall"
        return 1
    fi
}

# 35026: Ensure Power Nap Is Disabled for Intel Macs
fix_rule_35026_macos() {
    info_message "Applying fix for rule 35026_macos: Disable Power Nap"

    print_step 1 "Disabling Power Nap via pmset"
    if maybe_sudo pmset -a powernap 0; then
        debug_message "pmset applied; verifying with 'pmset -g custom'"
        local output
        output=$(pmset -g custom 2>/dev/null || true)
        if echo "$output" | grep -qE '\\bpowernap\\s+1\\b'; then
            error_message "Verification failed: powernap still set to 1"
            return 1
        else
            success_message "Power Nap disabled"
            return 0
        fi
    else
        error_message "Failed to apply pmset configuration"
        return 1
    fi
}

# 35030: Ensure Login Window Displays as Name and Password Is Enabled
fix_rule_35030_macos() {
    info_message "Applying fix for rule 35030_macos: Login window shows name and password"

    print_step 1 "Enabling SHOWFULLNAME via defaults"
    if maybe_sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true; then
        debug_message "defaults write succeeded; verifying..."
        local setting
        setting=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('SHOWFULLNAME')" 2>/dev/null || echo "unset")
        debug_message "Verification readback: SHOWFULLNAME=${setting}"
        if [ "$setting" = "1" ] || [ "$setting" = "true" ]; then
            success_message "Login window set to show name and password"
            return 0
        else
            error_message "Verification failed: SHOWFULLNAME not enabled"
            return 1
        fi
    else
        error_message "Failed to enable SHOWFULLNAME"
        return 1
    fi
}

# 35029: Ensure a Custom Message for the Login Screen Is Enabled
fix_rule_35029_macos() {
    info_message "Applying fix for rule 35029_macos: Configure login window banner message"

    local banner_text
    banner_text="WARNING: This system is for authorized use only. All activities may be monitored and recorded. Unauthorized use is prohibited and may result in disciplinary action and/or civil or criminal penalties."

    print_step 1 "Setting LoginwindowText via defaults"
    if maybe_sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "$banner_text"; then
        debug_message "defaults write succeeded; verifying..."
        local verify
        verify=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('LoginwindowText')" 2>/dev/null || echo "unset")
        debug_message "Verification readback: LoginwindowText length=$(printf %s "$verify" | wc -c | tr -d ' ')"
        if [ -n "$verify" ] && [ "$verify" != "unset" ]; then
            success_message "Login window banner message configured"
            return 0
        else
            error_message "Verification failed: LoginwindowText not set"
            return 1
        fi
    else
        error_message "Failed to set LoginwindowText"
        return 1
    fi
}

# 35036: Ensure Security Auditing Is Enabled (auditd)
fix_rule_35036_macos() {
    info_message "Applying fix for rule 35036_macos: Enable macOS auditd and baseline config"

    print_step 1 "Loading auditd service"
    if ! maybe_sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist; then
        error_message "Failed to load auditd service"
        return 1
    fi

    print_step 2 "Copying baseline audit_control"
    if ! maybe_sudo cp /etc/security/audit_control.example /etc/security/audit_control; then
        error_message "Failed to copy baseline audit_control"
        return 1
    fi

    print_step 3 "Setting recommended audit flags (lo,aa)"
    if ! maybe_sudo sh -c 'echo "flags:lo,aa" > /etc/security/audit_control'; then
        error_message "Failed to set recommended audit flags"
        return 1
    fi

    success_message "auditd enabled and baseline configuration applied"
    return 0
}

# 35037: Ensure Security Auditing Flags For User-Attributable Events Are Configured
fix_rule_35037_macos() {
    info_message "Applying fix for rule 35037_macos: Configure audit flags"

    print_step 1 "Backing up current audit_control"
    if ! maybe_sudo cp /etc/security/audit_control /etc/security/audit_control.bak; then
        error_message "Failed to backup audit_control"
        return 1
    fi

    print_step 2 "Appending comprehensive audit flags"
    if ! maybe_sudo sh -c 'echo "flags:-all,ad,aa,lo" >> /etc/security/audit_control'; then
        error_message "Failed to append audit flags"
        return 1
    fi

    print_step 3 "Restarting auditd service"
    if ! maybe_sudo launchctl unload /System/Library/LaunchDaemons/com.apple.auditd.plist; then
        warn_message "Failed to unload auditd; proceeding to load"
    fi
    if ! maybe_sudo launchctl load /System/Library/LaunchDaemons/com.apple.auditd.plist; then
        error_message "Failed to load auditd"
        return 1
    fi

    success_message "Audit flags configured and service restarted"
    return 0
}

# 35039: Ensure Security Auditing Retention Is Enabled
fix_rule_35039_macos() {
    info_message "Applying fix for rule 35039_macos: Configure audit log retention policy"

    print_step 1 "Setting time-based retention to 60 days"
    if ! maybe_sudo sed -i '' '/^expire-after:/d' /etc/security/audit_control; then
        error_message "Failed to remove existing expire-after entries"
        return 1
    fi
    if ! maybe_sudo sh -c 'echo "expire-after:60d" >> /etc/security/audit_control'; then
        error_message "Failed to append expire-after:60d"
        return 1
    fi

    print_step 2 "Restarting auditd to apply changes"
    if ! maybe_sudo launchctl unload /System/Library/LaunchDaemons/com.apple.auditd.plist; then
        warn_message "Failed to unload auditd; proceeding to load"
    fi
    if ! maybe_sudo launchctl load /System/Library/LaunchDaemons/com.apple.auditd.plist; then
        error_message "Failed to load auditd"
        return 1
    fi

    success_message "Audit retention policy configured"
    return 0
}

# 35040: Ensure Bonjour Advertising Services Is Disabled
fix_rule_35040_macos() {
    info_message "Applying fix for rule 35040_macos: Disable Bonjour multicast advertisements"

    print_step 1 "Setting NoMulticastAdvertisements via defaults"
    if ! maybe_sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true; then
        error_message "Failed to set NoMulticastAdvertisements"
        return 1
    fi

    print_step 2 "Restarting mDNSResponder"
    if ! maybe_sudo killall -HUP mDNSResponder; then
        warn_message "Failed to HUP mDNSResponder"
    fi

    debug_message "Verifying NoMulticastAdvertisements setting"
    local verify
    verify=$(osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder').objectForKey('NoMulticastAdvertisements')" 2>/dev/null || echo "unset")
    debug_message "Verification readback: NoMulticastAdvertisements=${verify}"
    if [ "$verify" = "1" ]; then
        success_message "Bonjour multicast advertisements disabled"
        return 0
    else
        error_message "Verification failed: expected NoMulticastAdvertisements=1"
        return 1
    fi
}

# 35042: Ensure NFS Server Is Disabled
fix_rule_35042_macos() {
    info_message "Applying fix for rule 35042_macos: Disable NFS server"

    print_step 1 "Stopping nfsd service"
    maybe_sudo nfsd stop >/dev/null 2>&1 || warn_message "nfsd stop returned non-zero"

    print_step 2 "Disabling and unloading nfsd"
    maybe_sudo launchctl disable system/com.apple.nfsd >/dev/null 2>&1 || warn_message "launchctl disable returned non-zero"
    maybe_sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.nfsd.plist >/dev/null 2>&1 || warn_message "launchctl unload returned non-zero"

    print_step 3 "Removing NFS configuration files"
    maybe_sudo rm -f /etc/exports /etc/nfs.conf || warn_message "Failed to remove one or more NFS config files"

    print_step 4 "Creating restrictive nfs.conf"
    if ! maybe_sudo sh -c 'echo "nfs.server: REQUIRED_LINE=-N 127" > /etc/nfs.conf'; then
        warn_message "Failed to create restrictive /etc/nfs.conf"
    else
        maybe_sudo chmod 644 /etc/nfs.conf || warn_message "Failed to chmod /etc/nfs.conf"
    fi

    debug_message "Verifying NFS service and config removal"
    if launchctl list | grep -q com.apple.nfsd; then
        error_message "NFSD service still appears active"
        return 1
    fi
    if [ -f /etc/exports ]; then
        error_message "/etc/exports still exists"
        return 1
    fi
    success_message "NFS service disabled and configuration removed"
    return 0
}

#######################################
# Linux SCA Check Functions
#######################################

# 28500: Ensure /tmp is mounted as tmpfs with noexec,nosuid,nodev and 1777 permissions
check_rule_28500_linux() {
    info_message "Checking rule 28500_linux: Ensure /tmp is mounted as tmpfs with noexec,nosuid,nodev and 1777 permissions"

    local mount_output
    local permissions
    local is_tmpfs
    local has_noexec
    local has_nosuid
    local has_nodev

    debug_message "Checking if /tmp is mounted as tmpfs"
    mount_output=$(mount | grep " on /tmp type tmpfs " || true)
    if [ -n "$mount_output" ]; then
        is_tmpfs="true"
    else
        is_tmpfs="false"
    fi
    debug_message "is_tmpfs=$is_tmpfs"

    debug_message "Checking mount options"
    has_noexec=$(echo "$mount_output" | grep -w noexec || true)
    has_nosuid=$(echo "$mount_output" | grep -w nosuid || true)
    has_nodev=$(echo "$mount_output" | grep -w nodev || true)
    debug_message "noexec=${has_noexec:-missing}, nosuid=${has_nosuid:-missing}, nodev=${has_nodev:-missing}"

    debug_message "Checking permissions"
    permissions=$(stat -c %a /tmp 2>/dev/null || echo "0")
    debug_message "/tmp permissions=$permissions"

    if [ "$is_tmpfs" = "true" ] && [ -n "$has_noexec" ] && [ -n "$has_nosuid" ] && [ -n "$has_nodev" ] && [ "$permissions" = "1777" ]; then
        debug_message "Check passed"
        return 0
    else
        debug_message "Check failed"
        return 1
    fi
}

# 28523: Secure /dev/shm Configuration
check_rule_28523_linux() {
  info_message "Checking rule 28523_linux: Secure /dev/shm Configuration (nodev, noexec, nosuid)"
  
  local mount_info
  mount_info=$(findmnt --kernel /dev/shm | tail -n +2 || true)
  debug_message "findmnt output for /dev/shm: ${mount_info}"

  if echo "$mount_info" | grep -qE 'nodev' && \
     echo "$mount_info" | grep -qE 'noexec' && \
     echo "$mount_info" | grep -qE 'nosuid'; then
    debug_message "/dev/shm has required mount options."
    return 0
  else
    debug_message "/dev/shm is missing one or more required mount options."
    return 1
  fi
}

# 28526: AIDE is installed and configured
check_rule_28526_linux() {
  info_message "Checking rule 28526_linux: AIDE is installed and configured."

  if ! command -v aide >/dev/null 2>&1; then
    debug_message "AIDE binary not found in PATH."
    return 1
  else
    debug_message "AIDE is installed."
  fi

  if [ ! -f /var/lib/aide/aide.db ]; then
    debug_message "AIDE database (/var/lib/aide/aide.db) not found."
    return 1
  else
    debug_message "AIDE database exists."
  fi

  debug_message "AIDE is installed and its database is initialized."
  return 0
}

# 28528: Secure GRUB configuration file permissions
check_rule_28528_linux() {
  info_message "Checking rule 28528_linux: Secure GRUB configuration file permissions"
  local path perms owner group
  path="/boot/grub/grub.cfg"
  if [ ! -f "$path" ]; then
    debug_message "$path not found; system may use grub2 path or is non-grub system"
    return 1
  fi
  owner=$(stat -c %U "$path" 2>/dev/null || echo unknown)
  group=$(stat -c %G "$path" 2>/dev/null || echo unknown)
  perms=$(stat -c %a "$path" 2>/dev/null || echo 000)
  debug_message "grub.cfg owner=${owner}, group=${group}, perms=${perms}"
  if [ "$owner" = "root" ] && [ "$group" = "root" ] && { [ "$perms" = "400" ] || [ "$perms" = "600" ]; }; then
    return 0
  fi
  return 1
}

# 28552: Remove avahi-daemon if not required
check_rule_28552_linux() {
  info_message "Checking rule 28552_linux: avahi-daemon removal status"
  local active_service active_socket enabled_service enabled_socket pkg

  active_service=$(systemctl is-active avahi-daemon.service 2>/dev/null || true)
  active_socket=$(systemctl is-active avahi-daemon.socket 2>/dev/null || true)
  enabled_service=$(systemctl is-enabled avahi-daemon.service 2>/dev/null || true)
  enabled_socket=$(systemctl is-enabled avahi-daemon.socket 2>/dev/null || true)

  pkg=$(dpkg -l | grep -E '^ii\s+avahi-daemon\b' || true)

  debug_message "systemctl is-active (service): ${active_service}"
  debug_message "systemctl is-active (socket):  ${active_socket}"
  debug_message "systemctl is-enabled (service): ${enabled_service}"
  debug_message "systemctl is-enabled (socket):  ${enabled_socket}"
  debug_message "dpkg -l avahi-daemon: ${pkg:-not installed}"

  if [ -z "$pkg" ] && ! systemctl list-unit-files | grep -q '^avahi-daemon'; then
    return 0
  fi
  return 1
}

# 28553: Remove CUPS if not required
check_rule_28553_linux() {
  info_message "Checking rule 28553_linux: CUPS removal status"

  if dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' cups >/dev/null 2>&1; then
    debug_message "cups is installed"
    return 1
  else
    debug_message "cups not installed"
    return 0
  fi
}

# 28566: rsync removal or masking
check_rule_28566_linux() {
  info_message "Checking rule 28566_linux: rsync is removed or masked"
  if dpkg -s rsync 2>/dev/null | grep -q "install ok installed"; then
    debug_message "rsync package is installed"
    if systemctl list-unit-files 2>/dev/null | grep -q '^rsync.service'; then
      local masked active
      masked=$(systemctl is-enabled rsync 2>/dev/null || true)
      active=$(systemctl is-active rsync 2>/dev/null || true)
      debug_message "rsync service masked=${masked}, active=${active}"
      [ "$masked" = "masked" ] && [ "$active" != "active" ] && return 0 || return 1
    else
      return 0
    fi
  else
    debug_message "rsync package not installed"
    return 0
  fi
}

# 28570: Uninstall telnet and disable any telnet services
check_rule_28570_linux() {
  info_message "Checking rule 28570_linux: telnet packages and services removed"
  if dpkg -l | grep -E 'telnet|telnetd' >/dev/null 2>&1; then
    debug_message "Found telnet-related packages installed or residual configs present"
    return 1
  fi
  if systemctl list-unit-files | grep -q telnet; then
    local active
    active=$(systemctl is-active telnet.socket 2>/dev/null || true)
    debug_message "telnet.socket active=${active}"
    [ "$active" = "active" ] && return 1
  fi
  return 0
}

# 28574: Remove iptables-persistent and clean dependencies
check_rule_28574_linux() {
  info_message "Checking rule 28574_linux: iptables-persistent absence"

  if dpkg-query -s iptables-persistent >/dev/null 2>&1; then
    return 1
  else
    return 0
  fi
}

# 28575: UFW firewall setup and verification
check_rule_28575_linux() {
    info_message "Checking rule 28575_linux: UFW firewall setup and verification"

    if ! systemctl is-active --quiet ufw.service; then
        debug_message "ufw.service is not active"
        return 1
    fi
    debug_message "ufw.service is active"

    if ! systemctl is-enabled --quiet ufw.service; then
        debug_message "ufw.service is not enabled"
        return 1
    fi
    debug_message "ufw.service is enabled"

    if maybe_sudo ufw status | grep -q "Status: active"; then
        debug_message "ufw status shows active"
        return 0
    else
        debug_message "ufw status does not show active"
        return 1
    fi
}

# 28576: UFW loopback traffic configuration
check_rule_28576_linux() {
    info_message "Checking rule 28576_linux: UFW loopback traffic configuration"

    if ! dpkg -s ufw >/dev/null 2>&1; then
        warn_message "ufw package is not installed"
        return 1
    fi

    if ! grep -q "IPV6=yes" /etc/default/ufw; then
        warn_message "ufw IPv6 is not enabled"
        return 1
    fi
    debug_message "ufw IPv6 is enabled"

    local status_output
    status_output=$(maybe_sudo ufw status verbose 2>/dev/null || echo "")
    if ! echo "$status_output" | grep -q "Status: active"; then
        warn_message "ufw status is not active"
        return 1
    fi
    debug_message "ufw status is active"

    # Check for required rules in ufw status verbose output
    local rules_regexes=(
        "Anywhere \(v6\) on lo\s*ALLOW IN\s*Anywhere \(v6\)"
        "Anywhere \(v6\)\s*ALLOW OUT\s*Anywhere \(v6\) on lo"
        "Anywhere \(v6\)\s*DENY IN\s*::1"
        "Anywhere on lo\s*ALLOW IN\s*Anywhere"
        "Anywhere\s*DENY IN\s*127.0.0.0/8"
        "Anywhere\s*\t*ALLOW OUT\s*Anywhere on lo"
    )

    for regex in "${rules_regexes[@]}"; do
        if ! echo "$status_output" | grep -Pq "$regex"; then
            warn_message "Missing required UFW rule matching regex: $regex"
            return 1
        fi
    done
    debug_message "All required UFW rules are present"

    return 0
}

# 28590: auditd and audispd-plugins installation and service status
check_rule_28590_linux() {
    info_message "Checking rule 28590_linux: auditd and audispd-plugins installation and service status"

    if ! dpkg-query -s auditd >/dev/null 2>&1; then
        debug_message "auditd package is not installed"
        return 1
    fi
    debug_message "auditd package is installed"

    if ! dpkg-query -s audispd-plugins >/dev/null 2>&1; then
        debug_message "audispd-plugins package is not installed"
        return 1
    fi
    debug_message "audispd-plugins package is installed"

    if ! systemctl is-active --quiet auditd.service >/dev/null 2>&1; then
        debug_message "auditd.service is not active"
        return 1
    fi
    debug_message "auditd.service is active"
    if ! systemctl is-enabled --quiet auditd.service >/dev/null 2>&1; then
        debug_message "auditd.service is not enabled"
        return 1
    fi
    debug_message "auditd.service is enabled"

    return 0
}

# 28591: Ensure auditd service is active and enabled
check_rule_28591_linux() {
    info_message "Checking rule 28591_linux: auditd service active and enabled"

    if ! systemctl is-active --quiet auditd.service >/dev/null 2>&1; then
        debug_message "auditd.service is not active"
        return 1
    fi
    debug_message "auditd.service is active"

    if ! systemctl is-enabled --quiet auditd.service >/dev/null 2>&1; then
        debug_message "auditd.service is not enabled"
        return 1
    fi
    debug_message "auditd.service is enabled"

    success_message "auditd service active and enabled"
    return 0
}

# 28592: Configure GRUB2 to Enable Early Auditing (audit=1)
check_rule_28592_linux() {
    info_message "Checking rule 28592_linux: Configure GRUB2 to Enable Early Auditing (audit=1)"

    local kernel_ok=0
    local grub_ok=0

    debug_message "Checking kernel parameters"
    if cat /proc/cmdline | grep -ow "audit=1" >/dev/null 2>&1; then
        debug_message "Kernel parameter audit=1 found in /proc/cmdline"
        kernel_ok=1
    else
        debug_message "Kernel parameter audit=1 not found in /proc/cmdline"
    fi

    debug_message "Checking GRUB configuration"
    if grep -ow "GRUB_CMDLINE_LINUX_DEFAULT=.*audit=1" /etc/default/grub >/dev/null 2>&1; then
        debug_message "GRUB configuration found in /etc/default/grub"
        grub_ok=1
    else
        debug_message "GRUB configuration not found in /etc/default/grub"
    fi

    if [ $kernel_ok -eq 1 ] || [ $grub_ok -eq 1 ]; then
        success_message "audit=1 configured correctly"
        return 0
    else
        warn_message "audit=1 not configured correctly"
        return 1
    fi
}

# 28593: Configure audit_backlog_limit Kernel Parameter
check_rule_28593_linux() {
    info_message "Checking rule 28593_linux: Configure audit_backlog_limit Kernel Parameter"

    local grub_file
    for grub_file in $(find /boot -name "grub*.cfg" 2>/dev/null); do
        debug_message "Checking $grub_file"

        value=$(maybe_sudo grep -Po 'audit_backlog_limit=\K\d+' "$grub_file" | head -n1)
        debug_message "Found audit_backlog_limit value: $value"

        if [ -z "$value" ]; then
            debug_message "Missing audit_backlog_limit parameter in $grub_file"
            return 1
        fi

        if [ "$value" -lt 8192 ]; then
            debug_message "audit_backlog_limit parameter in $grub_file is $value, expected >= 8192"
            return 1
        fi
    done

    success_message "audit_backlog_limit configured correctly"
    return 0
}

# 28597: Configure audit rules for sudoers files monitoring
check_rule_28597_linux() {
    info_message "Checking rule 28597_linux: audit rules for sudoers files monitoring"

    if ! command -v auditctl >/dev/null 2>&1; then
        debug_message "auditctl command not available"
        return 1
    fi

    local audit_rules
    audit_rules=$(maybe_sudo auditctl -l 2>/dev/null || echo "")

    if ! echo "$audit_rules" | grep -qE '^-w /etc/sudoers -p wa -k scope'; then
        debug_message "Missing audit rule for /etc/sudoers"
        return 1
    fi
    if ! echo "$audit_rules" | grep -qE '^-w /etc/sudoers.d -p wa -k scope'; then
        debug_message "Missing audit rule for /etc/sudoers.d"
        return 1
    fi

    debug_message "Audit rules for sudoers files monitoring are configured correctly."
    return 0
}

# 28598: Audit Sudo Privilege Escalation
check_rule_28598_linux() {
    info_message "Checking rule 28598_linux: audit rules for sudo privilege escalation monitoring"

    print_step 1 "Checking auditd service status"
    if ! maybe_sudo systemctl status auditd >/dev/null 2>&1; then
        debug_message "auditd service is not running"
        return 1
    fi

    print_step 2 "Reading current audit rules"
    local audit_rules
    audit_rules=$(maybe_sudo auditctl -l 2>/dev/null || echo "")

    local archs terms
    archs=("b32")
    [[ $(uname -m) = "x86_64" ]] && archs=("b64" "b32")

    terms=("execve" "uid!=euid" "auid!=1" "user_emulation")

    for arch in "${archs[@]}"; do
        local rule_found=true
        for term in "${terms[@]}"; do
            if ! echo "$audit_rules" | grep -F "arch=$arch" | grep -F "$term" >/dev/null 2>&1; then
                debug_message "Missing $arch user_emulation audit rule: $term"
                rule_found=false
            fi
        done

        if [[ "$rule_found" ]]; then
            debug_message "$arch user_emulation audit rule is active"
        else
            return 1
        fi
    done

    success_message "Audit rules for sudo privilege escalation monitoring are configured correctly"
    return 0
}

# 28599: Audit System Time Changes
check_rule_28599_linux() {
    info_message "Checking rule 28599_linux: audit rules for system time changes"

    print_step 1 "Checking auditd service status"
    if ! maybe_sudo systemctl status auditd >/dev/null 2>&1; then
        debug_message "auditd service is not running"
        return 1
    fi

    print_step 2 "Reading current audit rules"
    local audit_rules
    audit_rules=$(maybe_sudo auditctl -l 2>/dev/null || echo "")

    local archs syscalls
    archs=("b32")
    [[ $(uname -m) = "x86_64" ]] && archs=("b64" "b32")

    if [ "$arch" = "b32" ] && [ "$(uname -m)" = "i686" ]; then
        syscalls=("adjtimex" "settimeofday" "clock_settime" "stime")
    else
        syscalls=("adjtimex" "settimeofday" "clock_settime")
    fi
    
    for arch in "${archs[@]}"; do
        for syscall in "${syscalls[@]}"; do
            if ! echo "$audit_rules" | grep -F "arch=$arch" | grep -F "$syscall" >/dev/null 2>&1; then
                error_message "Missing $arch time-change syscall rule: $syscall"
                return 1
            fi
        done
    done

    if ! echo "$audit_rules" | grep -Fq "/etc/localtime"; then
        debug_message "Missing /etc/localtime file watch"
        return 1
    fi

    success_message "Audit rules for system time changes are configured correctly"
    return 0
}

# 28601: Audit User/Group Files
check_rule_28601_linux() {
    info_message "Checking rule 28601_linux: audit rules for user/group files"

    print_step 1 "Checking auditctl service status"
    if ! systemctl is-active --quiet auditd.service >/dev/null 2>&1; then
        debug_message "auditd.service is not active"
        return 1
    fi

    print_step 2 "Checking auditctl command availability"
    if ! command -v auditctl >/dev/null 2>&1; then
        debug_message "auditctl command not available"
        return 1
    fi

    print_step 3 "Checking audit rules"
    local audit_rules
    audit_rules=$(maybe_sudo auditctl -l 2>/dev/null || echo "")

    local files="/etc/group /etc/passwd /etc/gshadow /etc/shadow /etc/security/opasswd"
    for file in $files; do
        if ! echo "$audit_rules" | grep -qE "^-w $file -p wa -k identity"; then
            debug_message "Missing audit rule for $file"
            return 1
        fi
    done

    success_message "Audit rules for user/group files configured correctly"
    return 0
}

# 28602: Audit Session Initiation Events
check_rule_28602_linux() {
    info_message "Checking rule 28602_linux: audit rules for session initiation events"

    print_step 1 "Checking auditctl service status"
    if ! systemctl is-active --quiet auditd.service >/dev/null 2>&1; then
        debug_message "auditd.service is not active"
        return 1
    fi

    print_step 2 "Checking auditctl command availability"
    if ! command -v auditctl >/dev/null 2>&1; then
        debug_message "auditctl command not available"
        return 1
    fi

    print_step 3 "Checking audit rules"
    local files="/var/run/utmp /var/log/wtmp /var/log/btmp"
    for file in $files; do
        if ! maybe_sudo auditctl -l | grep -qE "^-w $file -p wa -k session"; then
            debug_message "Missing audit rule for $file"
            return 1
        fi
    done

    success_message "Audit rules for session initiation events are configured correctly"
    return 0
}


# 28603: Audit Login/Logout Events
check_rule_28603_linux() {
    info_message "Checking rule 28603_linux: audit rules for login/logout events"

    print_step 1 "Checking auditctl service status"
    if ! systemctl is-active --quiet auditd.service >/dev/null 2>&1; then
        debug_message "auditd.service is not active"
        return 1
    fi

    print_step 2 "Checking auditctl command availability"
    if ! command -v auditctl >/dev/null 2>&1; then
        debug_message "auditctl command not available"
        return 1
    fi

    print_step 3 "Checking audit rules"
    local audit_rules
    audit_rules=$(maybe_sudo auditctl -l 2>/dev/null || echo "")

    local files="/var/log/lastlog /var/run/faillock"
    for file in $files; do
        if ! echo "$audit_rules" | grep -qE "^-w $file -p wa -k logins"; then
            debug_message "Missing audit rule for $file"
            return 1
        fi
    done

    success_message "Audit rules for login/logout events are configured correctly"
    return 0
}

# 28605: Audit Immutable Mode
check_rule_28605_linux() {
    info_message "Checking rule 28605_linux: audit immutable mode configuration"

    print_step 1 "Checking auditctl service status"
    if ! systemctl is-active --quiet auditd.service >/dev/null 2>&1; then
        debug_message "auditd.service is not active"
        return 1
    fi

    print_step 2 "Checking auditctl command availability"
    if ! command -v auditctl >/dev/null 2>&1; then
        debug_message "auditctl command not available"
        return 1
    fi

    print_step 3 "Checking if audit is in immutable mode (enabled=2)"
    local audit_status
    audit_status=$(maybe_sudo auditctl -s 2>/dev/null | grep "enabled" || echo "")
    if ! echo "$audit_status" | grep -q "enabled 2"; then
        debug_message "Audit is not in immutable mode"
        return 1
    fi

    print_step 4 "Checking if -e 2 rule exists in rules files"
    if ! maybe_sudo grep -r "^-e\s\+2$" /etc/audit/rules.d/ >/dev/null 2>&1; then
        debug_message "Immutable mode rule does not exist in rules files"
        return 1
    fi

    success_message "Audit immutable mode configured successfully"
    return 0
}

# 28611: Audit Tools Ownership Configuration
check_rule_28611_linux() {
    info_message "Checking rule 28611_linux: audit tools ownership configuration"

    local audit_tools="/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules"
    local tool
    
    for tool in $audit_tools; do
        if [ -f "$tool" ]; then
            local owner
            owner=$(stat -c "%U" "$tool" 2>/dev/null)
            if [ "$owner" != "root" ]; then
                debug_message "$tool is not owned by root (current owner: $owner)"
                return 1
            fi
        fi
    done

    success_message "Audit tools ownership configured successfully"
    return 0
}

# 28613: AIDE Monitoring for Audit Tools
check_rule_28613_linux() {
    info_message "Checking rule 28613_linux: AIDE monitoring for audit tools"

    local audit_tools=(
        "/sbin/auditctl"
        "/sbin/auditd"
        "/sbin/ausearch"
        "/sbin/aureport"
        "/sbin/autrace"
        "/sbin/augenrules"
    )
    local missing=0

    print_step 1 "Checking AIDE configuration for audit tools"
    for tool in "${audit_tools[@]}"; do
        if ! maybe_sudo grep -E "^\s*${tool}\s+.*p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512" /etc/aide/aide.conf >/dev/null 2>&1; then
            error_message "Missing or incorrect AIDE entry for $tool"
            missing=1
        fi
    done

    if [ $missing -eq 0 ]; then
        success_message "All audit tools are correctly monitored by AIDE"
        return 0
    else
        debug_message "One or more audit tool entries are missing or incorrect"
        return 1
    fi
}

# 28617: Enable Log Compression in systemd-journald
check_rule_28617_linux() {
    info_message "Checking rule 28617_linux: systemd-journald log compression"

    if ! systemctl is-active --quiet systemd-journald; then
        debug_message "systemd-journald is not active"
        return 1
    fi

    if grep -E '^\s*Compress=yes' /etc/systemd/journald.conf >/dev/null 2>&1; then
        success_message "Log compression enabled in systemd-journald"
        return 0
    fi

    error_message "Log compression not enabled in systemd-journald"
    return 1
}

# 28618: Configure Persistent Logging for systemd-journald
check_rule_28618_linux() {
    info_message "Checking rule 28618_linux: systemd-journald persistent logging"

    if ! systemctl is-active --quiet systemd-journald; then
        debug_message "systemd-journald is not active"
        return 1
    fi

    if ! grep -E '^\s*Storage=persistent' /etc/systemd/journald.conf >/dev/null 2>&1; then
        error_message "Persistent logging not configured in systemd-journald"
        return 1
    fi

    success_message "systemd-journald persistent logging configured successfully"
    return 0
}

# 28623: Configure RSyslog File Permissions
check_rule_28623_linux() {
    info_message "Checking rule 28623_linux: RSyslog file permissions configuration"

    if ! systemctl is-active --quiet rsyslog; then
        debug_message "rsyslog is not active"
        return 1
    fi

    if ! grep -r --include='*.conf' '^\s*\$FileCreateMode\s\+0\?6[0-4]0' /etc/rsyslog.conf /etc/rsyslog.d/ >/dev/null 2>&1; then
        error_message "RSyslog FileCreateMode not configured to 0640 or stricter"
        return 1
    fi

    success_message "RSyslog file permissions configured successfully"
    return 0
}

# 28626: Secure /etc/crontab Permissions and Ownership
check_rule_28626_linux() {
    info_message "Checking rule 28626_linux: /etc/crontab permissions and ownership"

    if [ ! -f "/etc/crontab" ]; then
        debug_message "/etc/crontab does not exist"
        return 0 # Not applicable if file doesn't exist
    fi

    local perms owner group
    perms=$(stat -c "%a" /etc/crontab 2>/dev/null)
    owner=$(stat -c "%U" /etc/crontab 2>/dev/null)
    group=$(stat -c "%G" /etc/crontab 2>/dev/null)

    if [ "$perms" != "600" ] || [ "$owner" != "root" ] || [ "$group" != "root" ]; then
        debug_message "/etc/crontab has incorrect permissions ($perms) or ownership ($owner:$group)"
        return 1
    fi

    success_message "/etc/crontab permissions and ownership are correct"
    return 0
}

# 28627: Secure /etc/cron.hourly Directory Permissions and Ownership
check_rule_28627_linux() {
    info_message "Checking rule 28627_linux: /etc/cron.hourly directory permissions and ownership"

    if [ ! -d "/etc/cron.hourly" ]; then
        debug_message "/etc/cron.hourly does not exist"
        return 0  # Not applicable if directory doesn't exist
    fi

    local perms owner group
    perms=$(stat -c "%a" /etc/cron.hourly 2>/dev/null)
    owner=$(stat -c "%U" /etc/cron.hourly 2>/dev/null)
    group=$(stat -c "%G" /etc/cron.hourly 2>/dev/null)

    if [ "$perms" != "700" ] || [ "$owner" != "root" ] || [ "$group" != "root" ]; then
        error_message "/etc/cron.hourly has incorrect permissions ($perms) or ownership ($owner:$group)"
        return 1
    fi

    success_message "/etc/cron.hourly directory permissions and ownership are correct"
    return 0
}

# 28632: Configure cron allow/deny
check_rule_28632_linux() {
    info_message "Checking rule 28632_linux: cron allow/deny configuration"

    print_step 1 "Checking /etc/cron.deny"
    if [ -f /etc/cron.deny ]; then
        error_message "/etc/cron.deny exists"
        return 1
    fi

    print_step 2 "Checking /etc/cron.allow existence"
    if [ ! -f /etc/cron.allow ]; then
        error_message "/etc/cron.allow does not exist"
        return 1
    else
        success_message "/etc/cron.allow exists"
        
        print_step 3 "Checking /etc/cron.allow permissions and ownership"
        perms=$(stat -c "%a" /etc/cron.allow)
        owner=$(stat -c "%U:%G" /etc/cron.allow)

        if [ "$perms" != "640" ]; then
            error_message "Incorrect permissions on /etc/cron.allow (expected 640, got $perms)"
            return 1
        fi

        if [ "$owner" != "root:root" ]; then
            error_message "Incorrect ownership on /etc/cron.allow (expected root:root, got $owner)"
            return 1
        fi
    fi

    success_message "Cron configuration is compliant"
    return 0
}

# 28634: Secure /etc/ssh/sshd_config Ownership and Permissions
check_rule_28634_linux() {
    info_message "Checking rule 28634_linux: /etc/ssh/sshd_config permissions and ownership"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        debug_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    local perms owner group
    perms=$(stat -c "%a" /etc/ssh/sshd_config 2>/dev/null)
    owner=$(stat -c "%U" /etc/ssh/sshd_config 2>/dev/null)
    group=$(stat -c "%G" /etc/ssh/sshd_config 2>/dev/null)

    if [ "$perms" != "600" ] || [ "$owner" != "root" ] || [ "$group" != "root" ]; then
        error_message "/etc/ssh/sshd_config has incorrect permissions ($perms) or ownership ($owner:$group)"
        return 1
    fi

    success_message "/etc/ssh/sshd_config permissions and ownership are correct"
    return 0
}

# 28635: Configure SSH Access Restriction
check_rule_28635_linux() {
    info_message "Checking rule 28635_linux: SSH access restriction configuration"

    print_step 1 "Checking active SSH configuration"
    if ! maybe_sudo sshd -T 2>/dev/null | grep -Ei "^\s*(allowusers|denyusers|allowgroups|denygroups)\s+" >/dev/null 2>&1; then
        error_message "No SSH access restriction directives found in active configuration"
        return 1
    fi

    print_step 2 "Checking /etc/ssh/sshd_config"
    if ! maybe_sudo grep -Ei "^\s*(AllowUsers|DenyUsers|AllowGroups|DenyGroups)\s+" /etc/ssh/sshd_config >/dev/null 2>&1; then
        error_message "No restriction directives found in /etc/ssh/sshd_config"
        return 1
    fi

    print_step 3 "Checking /etc/ssh/sshd_config.d/"
    if ! maybe_sudo grep -REi "^\s*(AllowUsers|DenyUsers|AllowGroups|DenyGroups)\s+" /etc/ssh/sshd_config.d/*.conf >/dev/null 2>&1; then
        error_message "No restriction directives found in /etc/ssh/sshd_config.d/*.conf"
        return 1
    fi

    success_message "SSH access restriction is configured correctly"
    return 0
}

# 28638: SSH Disable Root Login
check_rule_28638_linux() {
    info_message "Checking rule 28638_linux: SSH disable root login"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        debug_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    if ! maybe_sudo sshd -T | grep -q "permitrootlogin no"; then
        debug_message "PermitRootLogin is not set to 'no'"
        return 1
    fi

    success_message "SSH root login is disabled"
    return 0
}

# 28645: SSH Disable Weak MAC Algorithms
check_rule_28645_linux() {
    info_message "Checking rule 28645_linux: SSH disable weak MAC algorithms"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

   if maybe_sudo sshd -T 2>/dev/null | grep -E "(hmac-md5|hmac-md5-96|hmac-sha1|hmac-sha1-96|umac-64|umac-128)" >/dev/null 2>&1; then
        error_message "Weak MAC algorithms detected"
        return 1
    fi

    success_message "SSH weak MAC algorithms are disabled"
    return 0
}

# 28647: SSH Disable Port Forwarding
check_rule_28647_linux() {
    info_message "Checking rule 28647_linux: SSH disable port forwarding"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        debug_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    if maybe_sudo sshd -T | grep -qE 'allowtcpforwarding yes'; then
        error_message "AllowTcpForwarding is not set to 'no'"
        return 1
    fi

    success_message "AllowTcpForwarding is set to 'no'"
    return 0
}

# 28648: SSH Banner Configuration
check_rule_28648_linux() {
    info_message "Checking rule 28648_linux: SSH banner configuration"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    if ! maybe_sudo grep -E '^Banner\s+/etc/issue.net' /etc/ssh/sshd_config >/dev/null 2>&1; then
        error_message "SSH banner not configured to /etc/issue.net"
        return 1
    fi

    if [ ! -f "/etc/issue.net" ]; then
        error_message "/etc/issue.net does not exist"
        return 1
    fi

    success_message "SSH banner configured correctly"
    return 0
}

# 28649: SSH MaxAuthTries Configuration
check_rule_28649_linux() {
    info_message "Checking rule 28649_linux: SSH MaxAuthTries configuration"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        debug_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    local max_auth_tries
    max_auth_tries=$(sshd -T 2>/dev/null | grep -i "maxauthtries" | awk '{print $2}')
    if [ "$max_auth_tries" -gt 4 ] 2>/dev/null; then
        debug_message "MaxAuthTries is greater than 4 (current: $max_auth_tries)"
        return 1
    fi

    success_message "MaxAuthTries is less than or equal to 4"
    return 0
}

# 28650: SSH MaxStartups Configuration
check_rule_28650_linux() {
    info_message "Checking rule 28650_linux: SSH MaxStartups configuration"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        debug_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    if ! maybe_sudo sshd -T 2>/dev/null | grep -qE 'maxstartups\s+10:30:60'; then
        error_message "MaxStartups is not set to '10:30:60'"
        return 1
    fi

    success_message "SSH MaxStartups is correctly configured"
    return 0
}

# 28652: SSH LoginGraceTime Configuration
check_rule_28652_linux() {
    info_message "Checking rule 28652_linux: SSH LoginGraceTime configuration"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        debug_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    local login_grace_time
    login_grace_time=$(maybe_sudo sshd -T 2>/dev/null | grep -i "logingracetime" | awk '{print $2}')
    if [[ login_grace_time -gt 60 ]] || [[ login_grace_time -eq 0 ]]; then
        error_message "LoginGraceTime is not between 1-60"
        return 1
    fi

    success_message "SSH LoginGraceTime is correctly configured"
    return 0
}

# 28653: SSH Session Timeout Configuration
check_rule_28653_linux() {
    info_message "Checking rule 28653_linux: SSH session timeout configuration"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        debug_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    local client_alive_interval client_alive_count_max
    client_alive_interval=$(maybe_sudo sshd -T 2>/dev/null | grep -i "clientaliveinterval" | awk '{print $2}')
    client_alive_count_max=$(maybe_sudo sshd -T 2>/dev/null | grep -i "clientalivecountmax" | awk '{print $2}')

    if [ "$client_alive_interval" -eq 0 ] 2>/dev/null || [ "$client_alive_count_max" -eq 0 ] 2>/dev/null; then
        error_message "SSH session timeout not properly configured"
        return 1
    fi

    success_message "SSH session timeout is correctly configured"
    return 0
}

# 28660: Restrict su command usage
check_rule_28660_linux() {
    info_message "Checking rule 28660_linux: Restrict su command usage"

    local pam_file="/etc/pam.d/su"
    
    if [ ! -f "$pam_file" ]; then
        error_message "PAM file $pam_file not found."
        return 1
    fi

    debug_message "Checking PAM configuration for su restriction in $pam_file."
    local wheel_line=$(grep -E 'auth\s+required\s+pam_wheel.so\s+use_uid' "$pam_file" | head -1)
    
    if [ -z "$wheel_line" ]; then
        error_message "PAM configuration for su restriction not found in $pam_file."
        return 1
    fi

    local group=$(echo "$wheel_line" | grep -oE 'group=[^[:space:]]+' | cut -d= -f2)
    
    if [ -z "$group" ]; then
        group="wheel"
    fi

    if echo "$wheel_line" | grep -q '^[[:space:]]*#'; then
        error_message "PAM su restriction is commented out in $pam_file."
        return 1
    fi
    if ! getent group "$group" >/dev/null 2>&1; then
        error_message "Group '$group' does not exist."
        return 1
    fi

    if getent group "$group" | awk -F: '{print $4}' | grep -q '.\+'; then
        error_message "Group '$group' is not empty - su command is not properly restricted."
        return 1
    fi

    success_message "PAM su restriction configuration is compliant."
    return 0
}

# 28661: Configure password policy with pam_pwquality
check_rule_28661_linux() {
    info_message "Checking rule 28661_linux: password policy with pam_pwquality"

    debug_message "Checking if libpam-pwquality is installed"
    if ! dpkg -l | grep -q libpam-pwquality; then
        error_message "libpam-pwquality is not installed"
        return 1
    fi

    debug_message "Checking password policy with pam_pwquality"
    if ! grep -E '^\s*minlen\s*=\s*14' /etc/security/pwquality.conf >/dev/null 2>&1; then
        error_message "minlen is not set to 14"
        return 1
    fi
    if ! grep -E '^\s*minclass\s*=\s*4' /etc/security/pwquality.conf >/dev/null 2>&1; then
        error_message "minclass is not set to 4"
        return 1
    fi

    success_message "Password policy is correctly configured (minlen=14, minclass=4)"
    return 0
}

# 28664: yescrypt password hashing
check_rule_28664_linux() {
    info_message "Checking rule 28664_linux: yescrypt password hashing"

    print_step 1 "Checking configuration files"
    if [ ! -f "/etc/login.defs" ]; then
        error_message "/etc/login.defs does not exist"
        return 1
    fi
    if [ ! -f "/etc/pam.d/common-password" ]; then
        error_message "/etc/pam.d/common-password does not exist"
        return 1
    fi

    print_step 2 "Checking PAM configuration"
    if ! grep -iP '^\s*ENCRYPT_METHOD\s+yescrypt' /etc/login.defs >/dev/null 2>&1; then
        error_message "ENCRYPT_METHOD is not set to yescrypt in /etc/login.defs"
        return 1
    fi
    if grep -P '^\s*password\s+.*pam_unix\.so.*(\syescrypt|\ssha512|\smd5|\sbigcrypt|\ssha256|\sblowfish)\s*' /etc/pam.d/common-password >/dev/null 2>&1; then
        error_message "Found explicit hashing algorithms in pam_unix.so configuration"
        return 1
    fi

    success_message "yescrypt password hashing is properly configured"
    return 0
}

# 28666: Configure password maximum age policy
check_rule_28666_linux() {
    info_message "Checking rule 28666_linux: Configure password maximum age policy"

    print_step 1 "Checking /etc/login.defs"
    if ! grep -E '^\s*PASS_MAX_DAYS\s+365' /etc/login.defs >/dev/null 2>&1; then
        error_message "PASS_MAX_DAYS is not set to 365"
        return 1
    fi
    if ! grep -E '^\s*PASS_MIN_DAYS\s+1' /etc/login.defs >/dev/null 2>&1; then
        error_message "PASS_MIN_DAYS is not set to 1"
        return 1
    fi

    print_step 2 "Checking user password expiry"
    if maybe_sudo awk -F: '($2 != "*" && $2 != "!*") {print $1, $5}' /etc/shadow | awk '$2 > 365 || $2 == "" {print}' | grep -q .; then
        error_message "Found users with password max age > 365 days"
        return 1
    fi

    success_message "Password maximum age configuration is compliant"
    return 0
}

#######################################
# Linux SCA Fix Functions
#######################################

# 28500: Configure /tmp as tmpfs with noexec,nosuid,nodev and 1777 permissions
fix_rule_28500_linux() {
    info_message "Applying fix for rule 28500_linux: Configure /tmp as tmpfs with noexec,nosuid,nodev and 1777 permissions"
    local fstab_file="/etc/fstab"
    local fstab_backup="/etc/fstab.bak"
    local tmpfs_line="tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0"

    print_step 1 "Backing up $fstab_file to $fstab_backup"
    if ! maybe_sudo cp "$fstab_file" "$fstab_backup"; then
        error_message "Failed to backup $fstab_file"
        return 1
    fi

    print_step 2 "Checking for existing /tmp entry in $fstab_file"
    if grep -q "^[^#].* /tmp " "$fstab_file"; then
        debug_message "Existing /tmp entry found, updating it"
        if ! maybe_sudo sed -i "/^[^#].* \/tmp /c\\$tmpfs_line" "$fstab_file"; then
            error_message "Failed to update $fstab_file"
            return 1
        fi
    else
        debug_message "No /tmp entry found, adding new entry"
        if ! echo "$tmpfs_line" | maybe_sudo tee -a "$fstab_file" >/dev/null; then
            error_message "Failed to update $fstab_file"
            return 1
        fi
    fi

    print_step 3 "Stopping services that may use /tmp"
    for service in snapd.service unattended-upgrades.service cron.service; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            maybe_sudo systemctl stop "$service" >/dev/null 2>&1 \
            || warn_message "Failed to stop $service, may cause issues."
        fi
    done

    debug_message "Attempting to unmount /tmp"
    if mountpoint -q /tmp; then
        if ! maybe_sudo umount -f /tmp; then
            error_message "Failed to unmount /tmp. Manual intervention may be required."
            return 1
        fi
    fi

    print_step 4 "Remounting all file systems from $fstab_file"
    if ! maybe_sudo mount -a; then
        error_message "Failed to mount all entries from $fstab_file. Restoring backup."
        maybe_sudo cp "$fstab_backup" "$fstab_file"
        return 1
    fi

    print_step 5 "Setting /tmp permissions to 1777"
    if ! maybe_sudo chmod 1777 /tmp; then
        error_message "Failed to set /tmp permissions to 1777"
        return 1
    fi

    success_message "Successfully configured /tmp with secure mount options"
    return 0
}

# 28523: Secure /dev/shm Configuration (nodev, noexec, nosuid)
fix_rule_28523_linux() {
  info_message "Applying fix for rule 28523_linux: Secure /dev/shm Configuration (nodev, noexec, nosuid)"

  local fstab_file="/etc/fstab"
  local fstab_line="tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,rw,relatime 0 0"

  print_step 1 "Checking and updating fstab entry for /dev/shm"
  if grep -qE '^[^#].*\s/dev/shm\s' "$fstab_file"; then
    debug_message "An existing, non-commented entry for /dev/shm was found. Replacing it."
    if ! maybe_sudo sed -i "s|^[^#].*\s/dev/shm\s.*$|$fstab_line|" "$fstab_file"; then
      error_message "Failed to replace the entry in $fstab_file. Please check permissions."
      return 1
    fi
    debug_message "Successfully replaced the entry in $fstab_file."
  else
    debug_message "No existing entry for /dev/shm found. Adding the fstab entry."
    if ! echo "$fstab_line" | maybe_sudo tee -a "$fstab_file" > /dev/null; then
      error_message "Failed to add the entry to $fstab_file. Please check permissions."
      return 1
    fi
    debug_message "Successfully added the entry to $fstab_file."
  fi

  print_step 2 "Remounting /dev/shm to apply the new options"
  if ! maybe_sudo mount -o remount /dev/shm; then
    error_message "Failed to remount /dev/shm. Please check the fstab entry and mount status."
    return 1
  fi
  
  info_message "Successfully remounted /dev/shm."
  success_message "Successfully secured /dev/shm configuration"
  return 0
}

# 28526: Configuring AIDE for file integrity monitoring
fix_rule_28526_linux() {
  info_message "Applying fix for rule 28526_linux: Configuring AIDE for file integrity monitoring."

  print_step 1 "Install AIDE and its dependencies"
  debug_message "Running apt-get update"
  maybe_sudo apt-get update >/dev/null 2>&1 || warn_message "apt-get update failed or produced warnings"
  
  debug_message "Installing AIDE"
  if ! DEBIAN_FRONTEND=noninteractive maybe_sudo apt-get install -y aide aide-common >/dev/null 2>&1; then
        error_message "Failed to install AIDE. Exiting."
        return 1
    else
        success_message "AIDE installed successfully."
    fi

  print_step 2 "Verifying installation"
  if ! maybe_sudo aide --version >/dev/null 2>&1; then
    error_message "Installation validation failed: aide --version did not succeed."
    return 1
  else
    debug_message "aide --version returned successfully."
  fi

  print_step 3 "Initializing database"
  if ! maybe_sudo aide --config=/etc/aide/aide.conf --init >/dev/null 2>&1; then
    error_message "Failed to initialize AIDE database. Exiting."
    return 1
  else
    debug_message "aideinit completed."
  fi

  print_step 4 "Activate the AIDE Database"
  if [ -f /var/lib/aide/aide.db.new ]; then
    debug_message "Found new AIDE database at /var/lib/aide/aide.db.new; moving into place."
    if ! maybe_sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; then
      error_message "Failed to activate AIDE database. Please check permissions."
      return 1
    else
      success_message "AIDE database successfully activated."
    fi
  else
    error_message "AIDE database initialization failed to create a new database file."
    return 1
  fi
}

# 28528: Secure GRUB configuration file permissions
fix_rule_28528_linux() {
  info_message "Applying fix for rule 28528_linux: Secure GRUB configuration file permissions"
  local path="/boot/grub/grub.cfg"

  print_step 1 "Ensuring root:root ownership on ${path}"
  if ! maybe_sudo chown root:root "$path"; then
    error_message "Failed to set ownership root:root on ${path}"
    return 1
  fi

  print_step 2 "Restricting permissions on ${path} to owner-only"
  if ! maybe_sudo chmod u-wx,go-rwx "$path"; then
    error_message "Failed to set restrictive permissions on ${path}"
    return 1
  fi

  debug_message "Verifying updated ownership and permissions"
  local perms owner group
  owner=$(stat -c %U "$path" 2>/dev/null || echo unknown)
  group=$(stat -c %G "$path" 2>/dev/null || echo unknown)
  perms=$(stat -c %a "$path" 2>/dev/null || echo 000)
  debug_message "Post-change: owner=${owner}, group=${group}, perms=${perms}"
  if [ "$owner" = "root" ] && [ "$group" = "root" ] && { [ "$perms" = "400" ] || [ "$perms" = "600" ]; }; then
    success_message "GRUB configuration permissions secured"
    return 0
  else
    error_message "Verification failed: ownership/perms not as expected"
    return 1
  fi
}

# 28552: Remove avahi-daemon if not required
fix_rule_28552_linux() {
  info_message "Applying fix for rule 28552_linux: Remove avahi-daemon"

  print_step 1 "Stop and disable avahi-daemon services"
  maybe_sudo systemctl stop avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || warn_message "Stop avahi returned non-zero"
  maybe_sudo systemctl disable avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || warn_message "Disable avahi returned non-zero"
  maybe_sudo systemctl mask avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || warn_message "Mask avahi returned non-zero"

  print_step 2 "Purge avahi-daemon packages"
  if ! maybe_sudo apt purge avahi-daemon -y >/dev/null 2>&1; then
    error_message "Failed to purge avahi-daemon"
    return 1
  fi

  print_step 3 "Verify avahi-daemon is removed"
  if dpkg -l | grep -E '^ii\s+avahi-daemon\b' >/dev/null 2>&1; then
    error_message "avahi-daemon still installed"
    return 1
  fi
  success_message "avahi-daemon removed and services disabled"
  return 0
}

# 28553: Remove CUPS if not required
fix_rule_28553_linux() {
  info_message "Applying fix for rule 28553_linux: Remove CUPS"

  print_step 1 "Stop and disable CUPS service"
  maybe_sudo systemctl stop cups >/dev/null 2>&1 || warn_message "Stopping cups returned non-zero"
  maybe_sudo systemctl disable cups >/dev/null 2>&1 || warn_message "Disabling cups returned non-zero"

  print_step 2 "Purge cups package"
  if ! maybe_sudo apt purge cups -y >/dev/null 2>&1; then
    error_message "Failed to purge cups"
    return 1
  fi

  print_step 3 "Autoremove unused dependencies"
  maybe_sudo apt autoremove -y >/dev/null 2>&1 || warn_message "apt autoremove returned non-zero"

  print_step 4 "Verify removal"
  if dpkg-query -s cups 2>/dev/null | grep -q "install ok installed"; then
    error_message "CUPS package still installed"
    return 1
  fi
  success_message "CUPS removed successfully"
  return 0
}

# 28566: rsync removal or masking
fix_rule_28566_linux() {
  info_message "Applying fix for rule 28566_linux: Remove or mask rsync"

  if dpkg -s rsync 2>/dev/null | grep -q "install ok installed"; then
    print_step 1 "Purging rsync package"
    if ! maybe_sudo apt purge rsync -y >/dev/null 2>&1; then
      warn_message "Failed to purge rsync; attempting to mask service instead"
      print_step 2 "Stopping and masking rsync service"
      maybe_sudo systemctl stop rsync >/dev/null 2>&1 || true
      maybe_sudo systemctl mask rsync >/dev/null 2>&1 || true
    fi
  else
    debug_message "rsync package not installed; checking for service"
    if systemctl list-unit-files | grep -q '^rsync.service'; then
      print_step 1 "Stopping and masking rsync service"
      maybe_sudo systemctl stop rsync >/dev/null 2>&1 || true
      maybe_sudo systemctl mask rsync >/dev/null 2>&1 || true
    fi
  fi

  success_message "rsync removed or masked as required"
  return 0
}

# 28570: Uninstall telnet and disable any telnet services
fix_rule_28570_linux() {
  info_message "Applying fix for rule 28570_linux: Remove telnet packages and services"

  print_step 1 "Stopping and disabling telnet services if present"
  maybe_sudo systemctl stop telnet.socket >/dev/null 2>&1 || true
  maybe_sudo systemctl disable telnet.socket >/dev/null 2>&1 || true

  print_step 2 "Purging telnet client and server packages"
  maybe_sudo apt purge telnet telnetd -y >/dev/null 2>&1 || true
  
  success_message "Telnet removed and services disabled"
  return 0
}

# 28574: Remove iptables-persistent and clean dependencies
fix_rule_28574_linux() {
  info_message "Applying fix for rule 28574_linux: Remove iptables-persistent"

  print_step 1 "Checking iptables-persistent package status"
  if dpkg-query -s iptables-persistent 2>/dev/null | grep -qi "is not installed"; then
    debug_message "iptables-persistent already not installed"
    return 0
  fi

  print_step 2 "Purging iptables-persistent and cleaning dependencies"
  if ! maybe_sudo apt purge iptables-persistent -y >/dev/null 2>&1; then
    error_message "Failed to purge iptables-persistent"
    return 1
  fi
  maybe_sudo apt autoremove -y >/dev/null 2>&1 || warn_message "apt autoremove returned non-zero"

  print_step 3 "Verify removal"
  if dpkg-query -s iptables-persistent 2>/dev/null | grep -qi "is not installed"; then
    success_message "iptables-persistent removed successfully"
    return 0
  else
    error_message "iptables-persistent still installed"
    return 1
  fi
}

# 28575: Setup and enable UFW firewall
fix_rule_28575_linux() {
    info_message "Applying fix for rule 28575_linux: Setup and enable UFW firewall"

    print_step 1 "Starting and enabling ufw.service"
    if ! maybe_sudo systemctl start ufw.service >/dev/null 2>&1; then
        error_message "Failed to start ufw.service"
        return 1
    fi
    debug_message "ufw started"

    if ! maybe_sudo systemctl enable ufw.service --now >/dev/null 2>&1; then
        error_message "Failed to enable ufw.service"
        return 1
    fi
    debug_message "ufw enabled on boot"

    print_step 2 "Enabling UFW firewall"
    if ! maybe_sudo ufw --force enable >/dev/null 2>&1; then
        error_message "Failed to enable UFW firewall"
        return 1
    fi
    debug_message "ufw firewall enabled"

    print_step 3 "Disabling conflicting firewalls (iptables, nftables)"
    if ! maybe_sudo systemctl stop iptables.service nftables.service >/dev/null 2>&1; then
        warn_message "Failed to stop iptables or nftables"
    fi
    if ! maybe_sudo systemctl disable iptables.service nftables.service >/dev/null 2>&1; then
        warn_message "Failed to disable iptables or nftables"
    fi

    success_message "UFW firewall setup and enabled successfully"
    return 0
}

# 28576: Configure UFW loopback traffic rules
fix_rule_28576_linux() {
    info_message "Applying fix for rule 28576_linux: Configure UFW loopback traffic rules"

    print_step 1 "Installing ufw package"
    if ! dpkg -s ufw >/dev/null 2>&1; then
        if ! maybe_sudo apt-get update >/dev/null 2>&1; then
            warn_message "apt-get update failed"
        fi
        if ! maybe_sudo apt-get install ufw -y >/dev/null 2>&1; then
            error_message "Failed to install ufw"
            return 1
        fi
    fi

    print_step 2 "Enabling ufw service"
    if ! systemctl is-active --quiet ufw.service; then
        if ! maybe_sudo systemctl unmask ufw.service; then
            error_message "Failed to unmask ufw.service"
            return 1
        fi
        if ! maybe_sudo systemctl --now enable ufw.service; then
            error_message "Failed to enable ufw.service"
            return 1
        fi
    fi

    print_step 3 "Allow incoming/outgoing traffic on loopback interface"
    if ! maybe_sudo ufw allow in on lo >/dev/null 2>&1; then
        error_message "Failed to allow incoming traffic on loopback interface"
        return 1
    fi
    if ! maybe_sudo ufw allow out on lo >/dev/null 2>&1; then
        error_message "Failed to allow outgoing traffic on loopback interface"
        return 1
    fi

    print_step 4 "Deny incoming loopback traffic on non-loopback interfaces (IPv4)"
    if ! maybe_sudo ufw deny in from 127.0.0.0/8 >/dev/null 2>&1; then
        error_message "Failed to deny incoming loopback traffic on non-loopback interfaces (IPv4)"
        return 1
    fi

    print_step 5 "Deny incoming loopback traffic on non-loopback interfaces (IPv6)"
    if ! maybe_sudo ufw deny in from ::1 >/dev/null 2>&1; then
        error_message "Failed to deny incoming loopback traffic on non-loopback interfaces (IPv6)"
        return 1
    fi

    print_step 6 "Reloading ufw"
    if ! maybe_sudo ufw reload >/dev/null 2>&1; then
        error_message "Failed to reload ufw"
        return 1
    fi

    success_message "UFW loopback traffic rules configured successfully"
    return 0
}

# 28590: Install and enable auditd and audispd-plugins
fix_rule_28590_linux() {
    info_message "Applying fix for rule 28590_linux: Install and enable auditd and audispd-plugins"

    print_step 1 "Installing auditd and audispd-plugins packages"
    if ! dpkg-query -s auditd >/dev/null 2>&1 || ! dpkg-query -s audispd-plugins >/dev/null 2>&1; then
        if ! maybe_sudo apt-get update >/dev/null 2>&1; then
            warn_message "apt-get update failed"
        fi
        if ! maybe_sudo apt-get install auditd audispd-plugins -y >/dev/null 2>&1; then
            error_message "Failed to install auditd or audispd-plugins"
            return 1
        fi
    fi

    print_step 2 "Enabling auditd service"
    if ! maybe_sudo systemctl enable auditd.service; then
        error_message "Failed to enable auditd.service"
        return 1
    fi

    print_step 3 "Starting auditd service"
    if ! maybe_sudo systemctl start auditd.service; then
        error_message "Failed to start auditd.service"
        return 1
    fi

    success_message "auditd and audispd-plugins installed and service enabled successfully"
    return 0
}

# 28591: Enable and start auditd service
fix_rule_28591_linux() {
    info_message "Applying fix for rule 28591_linux: Enable and start auditd service"

    print_step 1 "Enabling auditd.service"
    if ! maybe_sudo systemctl --now enable auditd.service >/dev/null 2>&1; then
        error_message "Failed to enable auditd.service"
        return 1
    fi

    success_message "auditd service enabled successfully"
    return 0
}

# 28592: Configure GRUB2 to Enable Early Auditing (audit=1)
fix_rule_28592_linux() {
    info_message "Applying fix for rule 28592_linux: Configure GRUB2 to Enable Early Auditing (audit=1)"
    local grub_config="/etc/default/grub"

    print_step 1 "Backup GRUB configuration"
    if ! maybe_sudo cp "$grub_config" "$grub_config.bakup.$(date +%Y%m%d)"; then
        error_message "Failed to backup GRUB configuration"
        return 1
    fi

    print_step 2 "Modifying GRUB configuration"
    if ! maybe_sudo sed -i \
        -e '/^GRUB_CMDLINE_LINUX_DEFAULT=/ {
                /audit=1/! s/"$/ audit=1"/
            }' "$grub_config"; then
        error_message "Failed to modify GRUB configuration"
        return 1
    fi

    print_step 3 "Update GRUB"
    if ! maybe_sudo update-grub >/dev/null 2>&1; then
        error_message "Failed to update GRUB"
        return 1
    fi

    success_message "GRUB configuration modified successfully"
    info_message "Reboot is required to apply the changes"
    return 0
}

# 28593: Configure audit_backlog_limit Kernel Parameter
fix_rule_28593_linux() {
    info_message "Applying fix for rule 28593_linux: Configure audit_backlog_limit Kernel Parameter"
    
    print_step 1 "Modifying GRUB_CMDLINE_LINUX"
    if maybe_sudo grep -q 'audit_backlog_limit=' /etc/default/grub; then
        if ! maybe_sudo sed -i 's/\(audit_backlog_limit=\)[0-9]\+/\18192/' /etc/default/grub; then
            error_message "Failed to update audit_backlog_limit value"
            return 1
        fi
    else
        if ! maybe_sudo sed -i 's/^\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 audit_backlog_limit=8192"/' /etc/default/grub; then
            error_message "Failed to append audit_backlog_limit to GRUB_CMDLINE_LINUX"
            return 1
        fi
    fi

    print_step 2 "Updating GRUB"
    if ! maybe_sudo update-grub >/dev/null 2>&1; then
        error_message "Failed to update GRUB"
        return 1
    fi

    success_message "audit_backlog_limit configured successfully"
    info_message "Reboot is required to apply the changes"
    return 0
}

# 28597: Configure audit rules for sudoers files monitoring
fix_rule_28597_linux() {
    info_message "Applying fix for rule 28597_linux: Add audit rules for sudoers files monitoring"

    print_step 1 "Creating audit rules file for sudoers monitoring"
    if ! printf -- "-w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d -p wa -k scope\n" | maybe_sudo tee /etc/audit/rules.d/50-sudoers-scope.rules >/dev/null; then
        error_message "Failed to create audit rules file"
        return 1
    fi

    print_step 2 "Loading audit rules"
    if ! maybe_sudo augenrules --load >/dev/null 2>&1; then
        error_message "Failed to load audit rules"
        return 1
    fi

    success_message "Audit rules for sudoers files monitoring configured successfully"
    if [[ $(maybe_sudo auditctl -s | grep "enabled") =~ "2" ]]; then
        info_message "Reboot required to fully activate audit rules."
    else
        info_message "Rules loaded successfully without reboot."
    fi
    return 0
}

# 28598: Audit Sudo Privilege Escalation
fix_rule_28598_linux() {
    info_message "Applying fix for rule 28598_linux: Add audit rules for sudo privilege escalation monitoring"

    print_step 1 "Backing up existing audit rules"
    if ! maybe_sudo mkdir /etc/audit/rules.d.backup >/dev/null 2>&1; then
        error_message "Failed to create backup directory"
        return 1
    fi
    if ! maybe_sudo cp -a /etc/audit/rules.d /etc/audit/rules.d.backup >/dev/null 2>&1; then
        error_message "Failed to backup existing audit rules"
        return 1
    fi

    print_step 2 "Creating audit rules file for user_emulation monitoring"
    case $(uname -m) in
        x86_64)
            if ! cat <<'EOF' | maybe_sudo tee /etc/audit/rules.d/50-user_emulation.rules >/dev/null 2>&1
# Monitor sudo privilege escalation (64-bit + 32-bit compatibility)
-a always,exit -F arch=b64 -C euid!=uid -F auid!=1 -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=1 -S execve -k user_emulation
EOF
            then
                error_message "Failed to create audit rules file"
                return 1
            fi
            ;;
        i686)
            if ! cat <<'EOF' | maybe_sudo tee /etc/audit/rules.d/50-user_emulation.rules >/dev/null 2>&1
# Monitor sudo privilege escalation (32-bit)
-a always,exit -F arch=b32 -C euid!=uid -F auid!=1 -S execve -k user_emulation
EOF
            then
                error_message "Failed to create audit rules file"
                return 1
            fi
            ;;
        *)
            error_message "Unsupported architecture: $(uname -m)"
            return 1
            ;;
    esac

    print_step 2 "Loading audit rules"
    if ! maybe_sudo augenrules --load >/dev/null 2>&1; then
        error_message "Failed to load audit rules"
        return 1
    fi

    if [[ $(maybe_sudo auditctl -s | grep "enabled") =~ "2" ]]; then
        info_message "Audit rules for sudo privilege escalation monitoring configured successfully, reboot required to apply the changes"
    else
        info_message "Audit rules for sudo privilege escalation monitoring configured successfully"
    fi
    return 0
}

# 28599: Audit System Time Changes
fix_rule_28599_linux() {
    info_message "Applying fix for rule 28599_linux: Add audit rules for system time changes"

    print_step 1 "Backing up existing rules"
    if ! maybe_sudo cp -a /etc/audit/rules.d /etc/audit/rules.d.backup >/dev/null 2>&1; then
        error_message "Failed to backup existing rules"
        return 1
    fi

    print_step 2 "Creating rules for time-change monitoring"
    case $(uname -m) in
        x86_64)
            if ! cat <<'EOF' | maybe_sudo tee /etc/audit/rules.d/50-time-change.rules >/dev/null 2>&1
# Monitor time-related system calls
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change

# Monitor local time file modifications
-w /etc/localtime -p wa -k time-change
EOF
            then
                error_message "Failed to create audit rules file"
                return 1
            fi
            ;;
        i686)
            if ! cat <<'EOF' | maybe_sudo tee /etc/audit/rules.d/50-time-change.rules >/dev/null 2>&1
# Monitor time-related system calls (including stime)
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change

# Monitor local time file modifications
-w /etc/localtime -p wa -k time-change
EOF
            then
                error_message "Failed to create audit rules file"
                return 1
            fi
            ;;
        *)
            error_message "Unsupported architecture: $(uname -m)"
            return 1
            ;;
    esac

    print_step 3 "Loading audit rules"
    if ! maybe_sudo augenrules --load >/dev/null 2>&1; then
        error_message "Failed to load audit rules"
        return 1
    fi

    if [[ $(maybe_sudo auditctl -s | grep "enabled") =~ "2" ]]; then
        info_message "Audit rules for system time changes configured successfully, reboot required to apply the changes"
    else
        info_message "Audit rules for system time changes configured successfully"
    fi
    return 0
}


# 28601: Audit User/Group Files
fix_rule_28601_linux() {
    info_message "Applying fix for rule 28601_linux: Add audit rules for user/group files"

    print_step 1 "Creating audit rules file for identity monitoring"
    local files="/etc/group /etc/passwd /etc/gshadow /etc/shadow /etc/security/opasswd"
    local rules="# Monitor user/group files\n"
    local rule_file="/etc/audit/rules.d/50-identity.rules"
    for file in $files; do
        rules+="-w $file -p wa -k identity\n"
    done
    if ! printf -- "$rules" | maybe_sudo tee "$rule_file" >/dev/null; then
        error_message "Failed to create audit rules file"
        return 1
    fi

    print_step 2 "Setting file permissions"
    maybe_sudo chmod 640 "$rule_file"
    maybe_sudo chown root:root "$rule_file"

    print_step 3 "Loading audit rules"
    if ! maybe_sudo augenrules --load >/dev/null 2>&1; then
        error_message "Failed to load audit rules"
        return 1
    fi

    if [[ $(maybe_sudo auditctl -s | grep "enabled") =~ "2" ]]; then
        info_message "Audit rules for user/group files configured successfully, reboot required to apply the changes"
    else
        info_message "Audit rules for user/group files configured successfully"
    fi
    return 0
}

# 28602: Audit Session Initiation Events
fix_rule_28602_linux() {
    info_message "Applying fix for rule 28602_linux: Add audit rules for session initiation events"

    print_step 1 "Creating audit rules file for session monitoring"
    local files="/var/run/utmp /var/log/wtmp /var/log/btmp"
    local rules="# Monitor session files\n"
    for file in $files; do
        rules+="-w $file -p wa -k session\n"
    done
    if ! printf -- "$rules" | maybe_sudo tee /etc/audit/rules.d/50-session.rules >/dev/null; then
        error_message "Failed to create audit rules file"
        return 1
    fi

    print_step 2 "Loading audit rules"
    if ! maybe_sudo augenrules --load >/dev/null 2>&1; then
        error_message "Failed to load audit rules"
        return 1
    fi

    print_step 3 "Restarting auditd service"
    if ! maybe_sudo systemctl restart auditd; then
        error_message "Failed to restart auditd service"
        return 1
    fi

    if [[ $(maybe_sudo auditctl -s | grep "enabled") =~ "2" ]]; then
        info_message "Audit rules for session initiation events configured successfully, reboot required to apply the changes"
    else
        info_message "Audit rules for session initiation events configured successfully"
    fi
    return 0
}

# 28603: Audit Login/Logout Events
fix_rule_28603_linux() {
    info_message "Applying fix for rule 28603_linux: Add audit rules for login/logout events"

    print_step 1 "Creating audit rules file for login monitoring"
    local files="/var/log/lastlog /var/run/faillock"
    local rules="# Monitor login/logout files\n"
    for file in $files; do
        rules+="-w $file -p wa -k logins\n"
    done
    if ! printf -- "$rules" | maybe_sudo tee /etc/audit/rules.d/50-login.rules >/dev/null; then
        error_message "Failed to create audit rules file"
        return 1
    fi

    print_step 2 "Loading audit rules"
    if ! maybe_sudo augenrules --load >/dev/null 2>&1; then
        error_message "Failed to load audit rules"
        return 1
    fi

    if [[ $(maybe_sudo auditctl -s | grep "enabled") =~ "2" ]]; then
        success_message "Audit rules for login/logout events configured successfully, reboot required to apply the changes"
    else
        success_message "Audit rules for login/logout events configured successfully"
    fi
    return 0
}

# 28605: Configure audit immutable mode
fix_rule_28605_linux() {
    info_message "Applying fix for rule 28605_linux: Configure audit immutable mode"

    print_step 1 "Adding immutable flag to audit rules"
    if ! maybe_sudo grep -r "^-e\s\+2$" /etc/audit/rules.d/ >/dev/null 2>&1; then
        if ! maybe_sudo bash -c 'printf -- "-e 2\n" >> /etc/audit/rules.d/99-finalize.rules' >/dev/null 2>&1; then
            error_message "Failed to add immutable flag to audit rules"
            return 1
        fi
    fi

    print_step 2 "Loading audit rules"
    if ! maybe_sudo augenrules --load >/dev/null 2>&1; then
        error_message "Failed to load audit rules"
        return 1
    fi

    print_step 3 "Checking if immutable mode is now active"
    if maybe_sudo auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        success_message "Audit immutable mode configured successfully"
        return 0
    else
        warn_message "Audit immutable mode rule created but may require reboot to take effect"
        return 0
    fi
}

# 28611: Audit Tools Ownership Configuration
fix_rule_28611_linux() {
    info_message "Applying fix for rule 28611_linux: Set audit tools ownership to root"

    local audit_tools="/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules"
    local tool
    local tools_found=""
    
    print_step 1 "Identifying existing audit tools"
    for tool in $audit_tools; do
        if [ -f "$tool" ]; then
            tools_found="$tools_found $tool"
        fi
    done
    
    if [ -z "$tools_found" ]; then
        error_message "No audit tools found. Install auditd package first."
        return 1
    fi
    
    print_step 2 "Setting ownership to root"
    if ! maybe_sudo chown root $tools_found 2>/dev/null; then
        error_message "Failed to set ownership of audit tools"
        return 1
    fi
    
    success_message "Audit tools ownership configured successfully"
    return 0
}

# 28613: Add AIDE monitoring for audit tools
fix_rule_28613_linux() {
    info_message "Applying fix for rule 28613_linux: Add AIDE monitoring for audit tools"

    print_step 1 "Backing up current AIDE configuration"
    if ! maybe_sudo cp /etc/aide/aide.conf /etc/aide/aide.conf.bak-$(date +%F) >/dev/null 2>&1; then
        error_message "Failed to backup AIDE configuration"
        return 1
    fi

    local audit_tools=(
        "/sbin/auditctl"
        "/sbin/auditd"
        "/sbin/ausearch"
        "/sbin/aureport"
        "/sbin/autrace"
        "/sbin/augenrules"
    )
    local required_attrs="p+i+n+u+g+s+b+acl+xattrs+sha512"

    print_step 2 "Updating AIDE configuration for audit tools"
    for tool in "${audit_tools[@]}"; do
        maybe_sudo sed -i "\|^${tool} |d" /etc/aide/aide.conf
        echo "${tool} ${required_attrs}" | maybe_sudo tee -a /etc/aide/aide.conf >/dev/null 2>&1
    done

    print_step 3 "Reinitializing AIDE database"
    if ! maybe_sudo aide --config=/etc/aide/aide.conf --init >/dev/null 2>&1; then
        error_message "Failed to initialize AIDE database"
        return 1
    fi

    if ! maybe_sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; then
        error_message "Failed to activate new AIDE database"
        return 1
    fi

    success_message "AIDE is now configured to monitor audit tools"
    return 0
}

# 28617: Enable Log Compression in systemd-journald
fix_rule_28617_linux() {
    info_message "Applying fix for rule 28617_linux: Enable log compression in systemd-journald"

    print_step 1 "Backing up journald configuration"
    maybe_sudo cp /etc/systemd/journald.conf /etc/systemd/journald.conf.bak

    print_step 2 "Configuring log compression"
    if grep -E '^\s*#?\s*Compress=' /etc/systemd/journald.conf >/dev/null 2>&1; then
        maybe_sudo sed -i 's/^\s*#\?\s*Compress=.*/Compress=yes/' /etc/systemd/journald.conf
    else
        maybe_sudo sed -i '/^\[Journal\]/a Compress=yes' /etc/systemd/journald.conf
    fi

    print_step 3 "Restarting systemd-journald"
    if ! maybe_sudo systemctl restart systemd-journald; then
        error_message "Failed to restart systemd-journald"
        return 1
    fi

    success_message "systemd-journald log compression enabled successfully"
    return 0
}

# 28618: Configure Persistent Logging for systemd-journald
fix_rule_28618_linux() {
    info_message "Applying fix for rule 28618_linux: Configure persistent logging for systemd-journald"

    print_step 1 "Backing up journald configuration"
    maybe_sudo cp /etc/systemd/journald.conf /etc/systemd/journald.conf.backup

    print_step 2 "Configuring persistent storage"
    if grep -E '^\s*#?\s*Storage=' /etc/systemd/journald.conf >/dev/null 2>&1; then
        maybe_sudo sed -i 's/^\s*#\?\s*Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
    else
        maybe_sudo sed -i '/^\[Journal\]/a Storage=persistent' /etc/systemd/journald.conf
    fi

    print_step 3 "Creating journal directory if needed"
    maybe_sudo mkdir -p /var/log/journal

    print_step 4 "Restarting systemd-journald"
    if ! maybe_sudo systemctl restart systemd-journald >/dev/null 2>&1; then
        error_message "Failed to restart systemd-journald"
        return 1
    fi

    success_message "systemd-journald persistent logging configured successfully"
    return 0
}

# 28623: Configure RSyslog File Permissions
fix_rule_28623_linux() {
    info_message "Applying fix for rule 28623_linux: Configure RSyslog file permissions"

    print_step 1 "Backing up rsyslog configuration"
    if ! maybe_sudo cp /etc/rsyslog.conf /etc/rsyslog.conf.bak; then
        error_message "Failed to backup rsyslog configuration"
        return 1
    fi
    
    print_step 2 "Creating rsyslog permissions configuration"
    if ! printf -- "# Set secure file permissions for new log files\n\$FileCreateMode 0640\n" | maybe_sudo tee /etc/rsyslog.d/50-default.conf >/dev/null; then
        error_message "Failed to create rsyslog permissions configuration"
        return 1
    fi

    print_step 3 "Restarting rsyslog service"
    if ! maybe_sudo systemctl restart rsyslog; then
        error_message "Failed to restart rsyslog service"
        return 1
    fi

    success_message "RSyslog file permissions configured successfully"
    return 0
}

# 28634: Secure /etc/ssh/sshd_config Ownership and Permissions
fix_rule_28634_linux() {
    info_message "Applying fix for rule 28634_linux: Secure /etc/ssh/sshd_config permissions and ownership"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    print_step 1 "Setting ownership to root:root"
    if ! maybe_sudo chown root:root /etc/ssh/sshd_config; then
        error_message "Failed to set ownership of /etc/ssh/sshd_config"
        return 1
    fi

    print_step 2 "Setting permissions to 600"
    if ! maybe_sudo chmod og-rwx /etc/ssh/sshd_config; then
        error_message "Failed to set permissions of /etc/ssh/sshd_config"
        return 1
    fi

    print_step 3 "Restarting SSH service"
    if ! maybe_sudo systemctl restart sshd; then
        error_message "Failed to restart SSH service"
        return 1
    fi

    success_message "/etc/ssh/sshd_config permissions and ownership secured successfully"
    return 0
}

# 28635: Configure SSH Access Restriction
fix_rule_28635_linux() {
    info_message "Applying fix for rule 28635_linux: Configure SSH access restriction"

    print_step 1 "Backing up SSH configuration"
    if ! maybe_sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak || \
       ! maybe_sudo cp -r /etc/ssh/sshd_config.d /etc/ssh/sshd_config.d.bak; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi

    print_step 2 "Adding SSH access restriction"
    local restrict_file="/etc/ssh/sshd_config.d/10-restrict-access.conf"
    local config_file="/etc/ssh/sshd_config"
    local directive="AllowGroups ssh-users"

    for file in "$restrict_file" "$config_file"; do
        if grep -qE "^[[:space:]]*${directive}[[:space:]]*$" "$file" >/dev/null 2>&1; then
            continue
        elif grep -qE "^[[:space:]]*#.*${directive}" "$file" >/dev/null 2>&1; then
            if ! maybe_sudo sed -i "s/^[[:space:]]*#.*${directive}/${directive}/" "$file" >/dev/null 2>&1; then
                error_message "Failed to uncomment restriction directive in $file"
                return 1
            fi
        else
            if ! echo "$directive" | maybe_sudo tee -a "$file" >/dev/null 2>&1; then
                error_message "Failed to append restriction directive to $file"
                return 1
            fi
        fi
    done

    print_step 3 "Ensuring /run/sshd directory exists"
    if ! ls -l /run/sshd >/dev/null 2>&1; then
        if ! maybe_sudo mkdir -p /run/sshd; then
            error_message "Failed to create /run/sshd directory"
            return 1
        fi
        if ! maybe_sudo chmod 0755 /run/sshd; then
            error_message "Failed to set permissions on /run/sshd directory"
            return 1
        fi
    fi

    print_step 4 "Testing SSH configuration"
    if ! maybe_sudo sshd -t; then
        error_message "SSH configuration syntax error — reverting backup"
        maybe_sudo mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        maybe_sudo rm -f "$restrict_file"
        return 1
    fi

    print_step 5 "Reloading SSH service"
    if ! maybe_sudo systemctl reload sshd >/dev/null 2>&1; then
        error_message "Failed to reload SSH service"
        return 1
    fi

    success_message "SSH access restriction applied"
    return 0
}

# 28638: Disable SSH Root Login
fix_rule_28638_linux() {
    info_message "Applying fix for rule 28638_linux: Disable SSH root login"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    print_step 1 "Backing up SSH configuration"
    if ! maybe_sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak >/dev/null 2>&1; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi

    print_step 2 "Configuring SSH root login restriction"
    if maybe_sudo grep -qE "^[[:space:]]*PermitRootLogin[[:space:]]+no([[:space:]]+.*)?$" /etc/ssh/sshd_config; then
        return 0
    elif maybe_sudo grep -qE "^[[:space:]]*#.*PermitRootLogin" /etc/ssh/sshd_config; then
        debug_message "Uncommenting PermitRootLogin directive in /etc/ssh/sshd_config"
        if ! maybe_sudo sed -i "s/^[[:space:]]*#.*PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config; then
            error_message "Failed to uncomment PermitRootLogin directive in /etc/ssh/sshd_config"
            return 1
        fi
    else
        debug_message "Appending PermitRootLogin directive to /etc/ssh/sshd_config"
        if ! echo "PermitRootLogin no" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null; then
            error_message "Failed to append PermitRootLogin directive to /etc/ssh/sshd_config"
            return 1
        fi
    fi

    print_step 3 "Ensuring /run/sshd directory exists"
    if ! ls -l /run/sshd >/dev/null 2>&1; then
        if ! maybe_sudo mkdir -p /run/sshd; then
            error_message "Failed to create /run/sshd directory"
            return 1
        fi
        if ! maybe_sudo chmod 0755 /run/sshd; then
            error_message "Failed to set permissions on /run/sshd directory"
            return 1
        fi
    fi

    print_step 4 "Testing SSH configuration syntax"
    if ! maybe_sudo sshd -t; then
        error_message "SSH configuration syntax error, Reverting backup"
        maybe_sudo mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        return 1
    fi

    print_step 5 "Restarting SSH service"
    if ! maybe_sudo systemctl restart sshd >/dev/null 2>&1; then
        error_message "Failed to restart SSH service"
        return 1
    fi

    success_message "SSH root login disabled successfully"
    return 0
}

# 28645: SSH Disable Weak MAC Algorithms
fix_rule_28645_linux() {
    info_message "Applying fix for rule 28645_linux: Disable weak SSH MAC algorithms"
    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi
    
    print_step 1 "Backing up SSH configuration"
    local backup_file="/etc/ssh/sshd_config.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/ssh/sshd_config $backup_file; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi
    
    print_step 2 "Configuring secure MAC algorithms"
    local secure_macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    maybe_sudo sed -i '/^\s*#\?\s*MACs/d' /etc/ssh/sshd_config
    if ! echo "MACs $secure_macs" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null; then
        error_message "Failed to configure secure MAC algorithms"
        return 1
    fi
    
    print_step 3 "Ensuring /run/sshd directory exists"
    if ! ls -l /run/sshd >/dev/null 2>&1; then
        if ! maybe_sudo mkdir -p /run/sshd; then
            error_message "Failed to create /run/sshd directory"
            return 1
        fi
        if ! maybe_sudo chmod 0755 /run/sshd; then
            error_message "Failed to set permissions on /run/sshd directory"
            return 1
        fi
    fi
    
    print_step 4 "Testing SSH configuration syntax"
    if ! maybe_sudo sshd -t; then
        error_message "SSH configuration syntax error, Reverting to backup"
        maybe_sudo cp $backup_file /etc/ssh/sshd_config
        return 1
    fi
    
    print_step 5 "Restarting SSH service"

    if command_exists systemctl; then
        if ! maybe_sudo systemctl restart sshd; then
            error_message "Failed to restart SSH service, Reverting to backup"
            maybe_sudo cp $backup_file /etc/ssh/sshd_config
            return 1
        fi
    elif command_exists service; then
        if ! maybe_sudo service ssh restart; then
            error_message "Failed to restart SSH service, Reverting to backup"
            maybe_sudo cp $backup_file /etc/ssh/sshd_config
            return 1
        fi
    else
        error_message "Failed to restart SSH service, Reverting to backup"
        maybe_sudo cp $backup_file /etc/ssh/sshd_config
        return 1
    fi
    
    success_message "SSH MAC algorithms configured successfully"
    return 0
}

# 28647: SSH Disable Port Forwarding
fix_rule_28647_linux() {
    info_message "Applying fix for rule 28647_linux: Disable SSH port forwarding"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    print_step 1 "Backing up SSH configuration"
    local backup_file="/etc/ssh/sshd_config.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/ssh/sshd_config "$backup_file"; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi

    print_step 2 "Configuring SSH forwarding settings"
    maybe_sudo sed -i '/^\s*#\?\s*AllowTcpForwarding/d' /etc/ssh/sshd_config
    if ! echo "AllowTcpForwarding no" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null; then
        error_message "Failed to configure AllowTcpForwarding"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 3 "Testing SSH configuration syntax"
    if ! maybe_sudo sshd -t >/dev/null 2>&1; then
        error_message "SSH configuration syntax error, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 4 "Restarting SSH service"
    if command_exists systemctl >/dev/null 2>&1; then
        if ! maybe_sudo systemctl restart sshd >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    elif command_exists service >/dev/null 2>&1; then
        if ! maybe_sudo service sshd restart >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    else
        error_message "Failed to restart SSH service, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    success_message "SSH port forwarding disabled successfully"
    return 0
}

fix_rule_28648_linux() {
    info_message "Applying fix for rule 28648_linux: Configure SSH banner"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    print_step 1 "Backing up SSH configuration"
    local backup_file="/etc/ssh/sshd_config.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/ssh/sshd_config "$backup_file"; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi

    print_step 2 "Creating banner file"
    local banner_content="WARNING: Unauthorized access to this system is prohibited.
All connections are monitored. By accessing this system, you consent to monitoring."
    
    if ! printf "%s\n" "$banner_content" | maybe_sudo tee /etc/issue.net >/dev/null; then
        error_message "Failed to create banner file"
        return 1
    fi

    print_step 3 "Setting banner file permissions"
    if ! maybe_sudo chmod 644 /etc/issue.net; then
        error_message "Failed to set banner file permissions"
        return 1
    fi
    
    if ! maybe_sudo chown root:root /etc/issue.net; then
        error_message "Failed to set banner file ownership"
        return 1
    fi

    print_step 4 "Configuring SSH banner"
    maybe_sudo sed -i '/^\s*#\?\s*Banner/d' /etc/ssh/sshd_config
    if ! echo "Banner /etc/issue.net" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null; then
        error_message "Failed to configure SSH banner"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 5 "Testing SSH configuration syntax"
    if ! maybe_sudo sshd -t; then
        error_message "SSH configuration syntax error, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 6 "Restarting SSH service"
    if command_exists systemctl; then
        if ! maybe_sudo systemctl restart sshd >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    elif command_exists service; then
        if ! maybe_sudo service sshd restart >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    else
        error_message "Failed to restart SSH service, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi
    
    success_message "SSH banner configured successfully"
    return 0
}

# 28649: SSH MaxAuthTries Configuration
fix_rule_28649_linux() {
    info_message "Applying fix for rule 28649_linux: Configure SSH MaxAuthTries"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    print_step 1 "Backing up SSH configuration"
    local backup_file="/etc/ssh/sshd_config.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/ssh/sshd_config "$backup_file"; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi

    print_step 2 "Configuring MaxAuthTries"
    maybe_sudo sed -i '/^\s*#\?\s*MaxAuthTries/d' /etc/ssh/sshd_config
    if ! echo "MaxAuthTries 4" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null 2>&1; then
        error_message "Failed to configure MaxAuthTries"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 3 "Testing SSH configuration syntax"
    if ! maybe_sudo sshd -t >/dev/null 2>&1; then
        error_message "SSH configuration syntax error, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 4 "Restarting SSH service"    
    if command_exists systemctl; then
        if ! maybe_sudo systemctl restart sshd >/dev/null 2>&1; then
            error_message "Failed to restart SSH service"
            return 1
        fi
    elif command_exists service; then
        if ! maybe_sudo service sshd restart >/dev/null 2>&1; then
            error_message "Failed to restart SSH service"
            return 1
        fi
    else
        error_message "Failed to restart SSH service, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi
    
    success_message "SSH MaxAuthTries configured successfully"
    return 0
}

# 28650: SSH MaxStartups Configuration
fix_rule_28650_linux() {
    info_message "Applying fix for rule 28650_linux: Configure SSH MaxStartups"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    print_step 1 "Backing up SSH configuration"
    local backup_file="/etc/ssh/sshd_config.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/ssh/sshd_config "$backup_file"; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi

    print_step 2 "Configuring SSH MaxStartups settings"
    maybe_sudo sed -i '/^\s*#\?\s*MaxStartups/d' /etc/ssh/sshd_config
    if ! echo "MaxStartups 10:30:60" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null; then
        error_message "Failed to configure MaxStartups"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 3 "Testing SSH configuration syntax"
    if ! maybe_sudo sshd -t >/dev/null 2>&1; then
        error_message "SSH configuration syntax error, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 4 "Restarting SSH service"
    if command_exists systemctl >/dev/null 2>&1; then
        if ! maybe_sudo systemctl restart sshd >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    elif command_exists service >/dev/null 2>&1; then
        if ! maybe_sudo service sshd restart >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    else
        error_message "Failed to restart SSH service, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    success_message "SSH MaxStartups configured successfully"
    return 0
}

# 28652: SSH LoginGraceTime Configuration
fix_rule_28652_linux() {
    info_message "Applying fix for rule 28652_linux: Configure SSH LoginGraceTime"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    print_step 1 "Backing up SSH configuration"
    local backup_file="/etc/ssh/sshd_config.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/ssh/sshd_config "$backup_file"; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi

    print_step 2 "Configuring SSH LoginGraceTime"
    maybe_sudo sed -i '/^\s*#\?\s*LoginGraceTime/d' /etc/ssh/sshd_config
    if ! echo "LoginGraceTime 60" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null; then
        error_message "Failed to configure LoginGraceTime"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 3 "Testing SSH configuration syntax"
    if ! maybe_sudo sshd -t >/dev/null 2>&1; then
        error_message "SSH configuration syntax error, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 4 "Restarting SSH service"
    if command_exists systemctl >/dev/null 2>&1; then
        if ! maybe_sudo systemctl restart sshd >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    elif command_exists service >/dev/null 2>&1; then
        if ! maybe_sudo service sshd restart >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    else
        error_message "Failed to restart SSH service, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    success_message "SSH LoginGraceTime configured successfully"
    return 0
}

# 28653: SSH Session Timeout Configuration
fix_rule_28653_linux() {
    info_message "Applying fix for rule 28653_linux: Configure SSH session timeout"

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        error_message "/etc/ssh/sshd_config does not exist"
        return 1
    fi

    print_step 1 "Backing up SSH configuration"
    local backup_file="/etc/ssh/sshd_config.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/ssh/sshd_config "$backup_file"; then
        error_message "Failed to backup SSH configuration"
        return 1
    fi

    print_step 2 "Configuring ClientAliveInterval"
    maybe_sudo sed -i '/^\s*#\?\s*ClientAliveInterval/d' /etc/ssh/sshd_config
    if ! echo "ClientAliveInterval 15" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null; then
        error_message "Failed to configure ClientAliveInterval"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 3 "Configuring ClientAliveCountMax"
    maybe_sudo sed -i '/^\s*#\?\s*ClientAliveCountMax/d' /etc/ssh/sshd_config
    if ! echo "ClientAliveCountMax 3" | maybe_sudo tee -a /etc/ssh/sshd_config >/dev/null; then
        error_message "Failed to configure ClientAliveCountMax"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 4 "Testing SSH configuration syntax"
    if ! maybe_sudo sshd -t >/dev/null 2>&1; then
        error_message "SSH configuration syntax error, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    print_step 5 "Restarting SSH service"
    if command_exists systemctl >/dev/null 2>&1; then
        if ! maybe_sudo systemctl restart sshd >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    elif command_exists service >/dev/null 2>&1; then
        if ! maybe_sudo service sshd restart >/dev/null 2>&1; then
            error_message "Failed to restart SSH service, reverting to backup"
            maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
            return 1
        fi
    else
        error_message "Failed to restart SSH service, reverting to backup"
        maybe_sudo cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi

    success_message "SSH session timeout configured successfully"
    return 0
}

# 28660: Restrict su command usage
fix_rule_28660_linux() {
    info_message "Applying fix for rule 28660_linux: Restrict su command usage."
    local pam_file="/etc/pam.d/su"
    local group
    local backup_file="$pam_file.bak-$(date +%F-%T)"

    group=$(grep -E 'pam_wheel\.so.*use_uid' "$pam_file" 2>/dev/null | head -1 | grep -oE 'group=[^[:space:]]+' | cut -d= -f2 | tr -d '\r' | xargs)
    group=${group:-"sugroup"}
    
    debug_message "Using group: '$group'"

    print_step 1 "Creating group '$group'."
    if getent group "$group" >/dev/null 2>&1; then
        debug_message "group $group exists, skipping creation"
    else
        if ! maybe_sudo groupadd "$group" >/dev/null 2>&1; then
            error_message "Failed to create group '$group'."
            return 1
        fi
    fi

    print_step 2 "Ensuring group '$group' is empty."
    local members
    members=$(getent group "$group" | awk -F: '{print $4}' | sed 's/,/ /g')
    if [ -n "$members" ] && [ "$members" != " " ]; then
        for user in $members; do
            if [ -n "$user" ]; then
                info_message "Removing user '$user' from '$group'."
                if ! maybe_sudo gpasswd -d "$user" "$group" >/dev/null 2>&1; then
                    error_message "Failed to remove user '$user' from '$group'."
                    return 1
                fi
            fi
        done
    else
        debug_message "Group '$group' is already empty."
    fi

    print_step 3 "Configuring PAM file '$pam_file'."

    if [ -f "$pam_file" ]; then
        debug_message "Backing up PAM file '$pam_file' to '$backup_file'"
        if ! maybe_sudo cp "$pam_file" "$backup_file" >/dev/null 2>&1; then
            error_message "Failed to backup '$pam_file'."
            return 1
        fi
    fi

    if grep -q "pam_wheel\.so.*use_uid" "$pam_file"; then
        debug_message "Existing pam_wheel.so configuration found."
        
        if ! maybe_sudo sed -i '/pam_wheel\.so.*use_uid/s/^[[:space:]]*#[[:space:]]*//' "$pam_file" >/dev/null 2>&1; then
            error_message "Failed to uncomment pam_wheel.so configuration."
            maybe_sudo mv "$backup_file" "$pam_file"
            return 1
        fi

        if ! grep -q "group=$group" "$pam_file"; then
            if ! maybe_sudo sed -i "/pam_wheel\.so.*use_uid/s/group=[^[:space:]]*/group=$group/g" "$pam_file" >/dev/null 2>&1; then
                if ! maybe_sudo sed -i "/pam_wheel\.so.*use_uid/s/use_uid/use_uid group=$group/" "$pam_file" >/dev/null 2>&1; then
                    error_message "Failed to update group in pam_wheel.so configuration."
                    maybe_sudo mv "$backup_file" "$pam_file"
                    return 1
                fi
            fi
        fi
    else
        debug_message "No pam_wheel.so configuration found, adding new configuration."
        local pam_line="auth required pam_wheel.so use_uid group=$group"
        
        if ! echo "$pam_line" | maybe_sudo tee -a "$pam_file" >/dev/null 2>&1; then
            error_message "Failed to add pam_wheel.so configuration."
            maybe_sudo mv "$backup_file" "$pam_file"
            return 1
        fi
    fi

    success_message "PAM su restriction configured successfully."    
    return 0
}

# 28661: Configure password policy with pam_pwquality
fix_rule_28661_linux() {
    info_message "Applying fix for rule 28661_linux: Configure password policy with pam_pwquality"

    print_step 1 "Installing libpam-pwquality if needed"
    if ! dpkg -l | grep -q libpam-pwquality; then
        debug_message "Updating package list"
        if ! maybe_sudo apt update >/dev/null 2>&1; then
            error_message "Failed to update package list"
            return 1
        fi
        debug_message "Installing libpam-pwquality"
        if ! maybe_sudo apt install -y libpam-pwquality >/dev/null 2>&1; then
            error_message "Failed to install libpam-pwquality"
            return 1
        fi
    fi

    print_step 2 "Backing up pwquality configuration"
    local backup_file="/etc/security/pwquality.conf.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/security/pwquality.conf "$backup_file" >/dev/null 2>&1; then
        error_message "Failed to backup pwquality configuration"
        return 1
    fi

    print_step 3 "Configuring minimum password length (minlen=14)"
    maybe_sudo sed -i '/^\s*#\?\s*minlen/d' /etc/security/pwquality.conf
    if ! echo "minlen = 14" | maybe_sudo tee -a /etc/security/pwquality.conf >/dev/null 2>&1; then
        error_message "Failed to configure minlen"
        maybe_sudo cp "$backup_file" /etc/security/pwquality.conf
        return 1
    fi

    print_step 4 "Configuring password complexity (minclass=4)"
    maybe_sudo sed -i '/^\s*#\?\s*minclass/d' /etc/security/pwquality.conf
    if ! echo "minclass = 4" | maybe_sudo tee -a /etc/security/pwquality.conf >/dev/null 2>&1; then
        error_message "Failed to configure minclass"
        maybe_sudo cp "$backup_file" /etc/security/pwquality.conf
        return 1
    fi

    success_message "Password policy configured successfully"
    return 0
}

# 28664: yescrypt password hashing
fix_rule_28664_linux() {
    info_message "Applying fix for rule 28664_linux: yescrypt password hashing"

    print_step 1 "Checking configuration files"
    if [ ! -f "/etc/login.defs" ]; then
        error_message "/etc/login.defs does not exist"
        return 1
    fi
    if [ ! -f "/etc/pam.d/common-password" ]; then
        error_message "/etc/pam.d/common-password does not exist"
        return 1
    fi

    print_step 2 "Backing up configuration files"
    local backup_timestamp="$(date +%F-%T)"
    local login_defs_backup="/etc/login.defs.bak-$backup_timestamp"
    local pam_backup="/etc/pam.d/common-password.bak-$backup_timestamp"

    print_step 3 "Backing up /etc/login.defs and /etc/pam.d/common-password"
    if ! maybe_sudo cp /etc/login.defs "$login_defs_backup"; then
        error_message "Failed to backup /etc/login.defs"
        return 1
    fi
    if ! maybe_sudo cp /etc/pam.d/common-password "$pam_backup"; then
        error_message "Failed to backup /etc/pam.d/common-password"
        return 1
    fi

    print_step 4 "Configuring ENCRYPT_METHOD in /etc/login.defs"
    maybe_sudo sed -i '/^\s*#\?\s*ENCRYPT_METHOD/d' /etc/login.defs
    if ! echo "ENCRYPT_METHOD yescrypt" | maybe_sudo tee -a /etc/login.defs >/dev/null 2>&1; then
        error_message "Failed to configure ENCRYPT_METHOD"
        maybe_sudo cp "$login_defs_backup" /etc/login.defs
        return 1
    fi

    print_step 5 "Configuring PAM password settings"
    if ! maybe_sudo sed -i '/^\s*password\s.*pam_unix\.so/ s/\s\+\(yescrypt\|sha512\|md5\|bigcrypt\|sha256\|blowfish\)\b//g' /etc/pam.d/common-password; then
        error_message "Failed to configure PAM password settings"
        maybe_sudo cp "$login_defs_backup" /etc/login.defs
        maybe_sudo cp "$pam_backup" /etc/pam.d/common-password
        return 1
    fi

    success_message "yescrypt password hashing configured successfully"
    return 0
}

# 28666: Configure password maximum age policy
fix_rule_28666_linux() {
    info_message "Applying fix for rule 28666_linux: Configure password maximum age policy"

    if [ ! -f "/etc/login.defs" ]; then
        error_message "/etc/login.defs does not exist"
        return 1
    fi

    print_step 1 "Backing up configuration"
    local backup_file="/etc/login.defs.bak-$(date +%F-%T)"
    if ! maybe_sudo cp /etc/login.defs "$backup_file"; then
        error_message "Failed to backup /etc/login.defs"
        return 1
    fi

    print_step 2 "Configuring password policy"
    maybe_sudo sed -i '/^\s*#\?\s*PASS_MAX_DAYS/d' /etc/login.defs
    maybe_sudo sed -i '/^\s*#\?\s*PASS_MIN_DAYS/d' /etc/login.defs
    if ! echo "PASS_MAX_DAYS 365" | maybe_sudo tee -a /etc/login.defs >/dev/null 2>&1; then
        error_message "Failed to configure PASS_MAX_DAYS"
        maybe_sudo cp "$backup_file" /etc/login.defs
        return 1
    fi
    if ! echo "PASS_MIN_DAYS 1" | maybe_sudo tee -a /etc/login.defs >/dev/null 2>&1; then
        error_message "Failed to configure PASS_MIN_DAYS"
        maybe_sudo cp "$backup_file" /etc/login.defs
        return 1
    fi

    print_step 3 "Updating existing users"
    if ! maybe_sudo awk -F: '($2 != "*" && $2 != "!*" && $5 > 365) {print $1}' /etc/shadow >> /tmp/users_to_update.txt; then
        error_message "Failed to update existing users"
        return 1
    fi
    if ! while read user; do maybe_sudo chage --maxdays 365 "$user"; done < /tmp/users_to_update.txt; then
        error_message "Failed to update existing users"
        return 1
    fi
    maybe_sudo rm /tmp/users_to_update.txt

    success_message "Password maximum age configuration completed successfully"
    return 0
}

#######################################
# Orchestrator Functions
#######################################

# Run all SCA checks and populate failed/passed arrays
run_sca_checks() {
    info_message "Running SCA checks for $OS_TYPE..."
    
    # Reset counters and arrays
    TESTS_PASSED=0
    TESTS_FAILED=0
    FAILED_CHECKS=""
    PASSED_CHECKS=""
    
    for check_id in $CHECKS; do
        local check_function="check_rule_${check_id}"
        
        # Check if function exists
        if command -v "$check_function" >/dev/null 2>&1; then
            if $check_function; then
                success_message "✓ Check $check_id passed"
                TESTS_PASSED=$((TESTS_PASSED + 1))
                if [ -z "$PASSED_CHECKS" ]; then
                    PASSED_CHECKS="$check_id"
                else
                    PASSED_CHECKS="$PASSED_CHECKS $check_id"
                fi
            else
                error_message "✗ Check $check_id failed"
                TESTS_FAILED=$((TESTS_FAILED + 1))
                if [ -z "$FAILED_CHECKS" ]; then
                    FAILED_CHECKS="$check_id"
                else
                    FAILED_CHECKS="$FAILED_CHECKS $check_id"
                fi
            fi
        else
            warn_message "Check function $check_function not implemented"
        fi
    done
    
    info_message "SCA checks completed: $TESTS_PASSED passed, $TESTS_FAILED failed"
}

# Run fixes for all failed checks
run_sca_fixes() {
    if [ -z "$FAILED_CHECKS" ]; then
        info_message "No failed checks to fix"
        return 0
    fi
    
    info_message "Running fixes for failed checks: $FAILED_CHECKS"
    
    for check_id in $FAILED_CHECKS; do
        local fix_function="fix_rule_${check_id}"
        
        # Check if fix function exists
        if command -v "$fix_function" >/dev/null 2>&1; then
            if $fix_function; then
                FIXES_APPLIED=$((FIXES_APPLIED + 1))
                success_message "✓ Fix for $check_id applied successfully"
            else
                warn_message "✗ Fix for $check_id failed"
            fi
        else
            warn_message "Fix function $fix_function not implemented for check $check_id"
        fi
    done
}

# Verify SCA fixes by re-running checks
verify_sca_fixes() {
    info_message "Verifying applied fixes..."
    
    # Store original failed checks
    local original_failed="$FAILED_CHECKS"
    
    # Re-run checks
    run_sca_checks
    
    # Compare results
    local fixed_count=0
    for check_id in $original_failed; do
        # Check if this check_id is no longer in FAILED_CHECKS
        case " $FAILED_CHECKS " in
            *" $check_id "*)
                warn_message "Check $check_id still failing after fix attempt"
                ;;
            *)
                success_message "Check $check_id now passes after fix"
                fixed_count=$((fixed_count + 1))
                ;;
        esac
    done
    
    info_message "Verification complete: $fixed_count checks were successfully fixed"
}

fix_rule_28626_linux() {
    info_message "Applying fix for rule 28626_linux: Secure /etc/crontab permissions and ownership"

    if [ ! -f "/etc/crontab" ]; then
        info_message "/etc/crontab does not exist, skipping"
        return 0
    fi

    print_step 1 "Setting ownership to root:root"
    if ! maybe_sudo chown root:root /etc/crontab; then
        error_message "Failed to set ownership of /etc/crontab"
        return 1
    fi

    print_step 2 "Setting permissions to 600"
    if ! maybe_sudo chmod og-rwx /etc/crontab; then
        error_message "Failed to set permissions of /etc/crontab"
        return 1
    fi

    success_message "/etc/crontab permissions and ownership secured successfully"
    return 0
}

# 28627: Secure /etc/cron.hourly Directory Permissions and Ownership
fix_rule_28627_linux() {
    info_message "Applying fix for rule 28627_linux: Secure /etc/cron.hourly directory permissions and ownership"

    if [ ! -d "/etc/cron.hourly" ]; then
        info_message "/etc/cron.hourly does not exist, skipping"
        return 0
    fi

    print_step 1 "Setting ownership to root:root"
    if ! maybe_sudo chown root:root /etc/cron.hourly; then
        error_message "Failed to set ownership of /etc/cron.hourly"
        return 1
    fi

    print_step 2 "Setting permissions to 700"
    if ! maybe_sudo chmod og-rwx /etc/cron.hourly; then
        error_message "Failed to set permissions of /etc/cron.hourly"
        return 1
    fi

    success_message "/etc/cron.hourly directory permissions and ownership secured successfully"
    return 0
}

# 28632: Configure cron allow/deny
fix_rule_28632_linux() {
    info_message "Applying fix for rule 28632_linux: cron allow/deny configuration"

    print_step 1 "Removing /etc/cron.deny"
    if [ -f /etc/cron.deny ]; then
        if ! maybe_sudo rm -f /etc/cron.deny; then
            error_message "Failed to remove /etc/cron.deny"
            return 1
        fi
    fi

    print_step 2 "Creating /etc/cron.allow"
    if [ ! -f /etc/cron.allow ]; then
        if ! maybe_sudo touch /etc/cron.allow; then
            error_message "Failed to create /etc/cron.allow"
            return 1
        fi
    fi

    print_step 3 "Setting permissions and ownership on /etc/cron.allow"
    if ! maybe_sudo chmod 0640 /etc/cron.allow; then
        error_message "Failed to set permissions on /etc/cron.allow"
        return 1
    fi
    if ! maybe_sudo chown root:root /etc/cron.allow; then
        error_message "Failed to set ownership on /etc/cron.allow"
        return 1
    fi

    success_message "Cron configuration fixed"
    return 0
}

#######################################
# Main execution functions
#######################################

show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION

DESCRIPTION:
    Automated Wazuh SCA remediation tool for applying fixes to failed checks

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    -l, --log-level LEVEL   Set log level (DEBUG, INFO, WARNING, ERROR)
    -h, --help              Show this help message

EXAMPLES:
    $SCRIPT_NAME                           # Run checks and apply fixes
    $SCRIPT_NAME --log-level DEBUG         # Run with debug logging

REQUIREMENTS:
    - Root privileges (script will use sudo if available)
    - Wazuh agent properly installed and configured

EOF
}

parse_arguments() {
    while [ $# -gt 0 ]; do
        case $1 in
            -l|--log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                error_message "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    case "$LOG_LEVEL" in
        DEBUG|INFO|WARNING|ERROR) ;;
        *) 
            error_message "Invalid log level: $LOG_LEVEL"
            exit 1
            ;;
    esac
}

# Generate and display summary
show_summary() {
    echo ""
    info_message "=== EXECUTION SUMMARY ==="
    info_message "Script: $SCRIPT_NAME v$SCRIPT_VERSION"
    info_message "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
    info_message "Fixes Applied: $FIXES_APPLIED"
    info_message "Tests Passed: $TESTS_PASSED"
    info_message "Tests Failed: $TESTS_FAILED"
    
    if [ -n "$FAILED_CHECKS" ]; then
        info_message "Still Failing: $FAILED_CHECKS"
    fi
    
    if [ -n "$PASSED_CHECKS" ]; then
        info_message "Passing: $PASSED_CHECKS"
    fi
    
    info_message "========================"
}

main() {
    parse_arguments "$@"
    
    info_message "Starting Wazuh SCA automation (v$SCRIPT_VERSION)"
    info_message "OS: $OS_TYPE, Log Level: $LOG_LEVEL"
    
    # Run initial SCA checks
    run_sca_checks
    
    # Apply fixes if there are failures
    if [ "$TESTS_FAILED" -gt 0 ]; then
        run_sca_fixes
        
        # Verify fixes were applied successfully
        verify_sca_fixes
    else
        success_message "All SCA checks passed - no fixes needed!"
    fi
    
    # Show final summary
    show_summary
    
    # Exit with appropriate code
    if [ "$TESTS_FAILED" -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Execute main function with all arguments
main "$@"