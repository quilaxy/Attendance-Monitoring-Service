using System;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace EventLogOutEmployeeService
{
    public sealed class ParsedSecurityEvent
    {
        public int EventId { get; init; }
        public string? Message { get; init; }
        public string? MessageExcerpt { get; init; }
        public int LogonType { get; init; }
        public string? Username { get; init; }
        public string? Sid { get; init; }
        public string? LogonId { get; init; }
    }

    public static class SecurityEventParser
    {
        private static readonly HashSet<string> InvalidUsernames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Akun sistem Windows standar
            "SYSTEM", "LOCAL SERVICE", "LOCAL_SYSTEM", "NETWORK SERVICE",
            "ANONYMOUS LOGON", "Guest", "DefaultAccount", "Administrator",
            // Nama Windows path component yang terbukti lolos lewat Pattern 3
            // karena ada di path executable di baris pertama event 1074
            // (misal C:\\WINDOWS\\servicing\\TrustedInstaller.exe → "servicing")
            "system32", "syswow64", "servicing", "winsxs", "uus",
            "trustedinstaller", "svchost", "services", "lsass", "winlogon",
            "explorer", "consent", "credpro"
        };

        private static readonly string[] InvalidUsernamePrefixes =
        {
            "DWM-", "UMFD-", "NT Service",
            // Path-relative prefixes yang kadang tersisa setelah NormalizeDisplayUsername
            "NT AUTHORITY", "BUILTIN"
        };

        public static ParsedSecurityEvent Parse(EventLogEntry entry)
        {
            int eventId = GetNormalizedEventId(entry);
            string? message = entry.Message;

            string? excerpt = null;
            if (!string.IsNullOrEmpty(message))
                excerpt = ExtractMessageSection(message, eventId, 600);

            int logonType = ((eventId == 4624 || eventId == 4634 || eventId == 4647) && message != null)
                ? ParseLogonType(message)
                : 0;

            string? username = message != null ? GetUsernameFromEvent(message, eventId) : null;
            string? sid = message != null ? GetUserSidFromSecurityEvent(message, eventId) : null;
            string? logonId =
                (eventId == 4624 || eventId == 4634 || eventId == 4647)
                    ? GetLogonId(excerpt ?? message)
                    : null;

            return new ParsedSecurityEvent
            {
                EventId = eventId,
                Message = message,
                MessageExcerpt = excerpt,
                LogonType = logonType,
                Username = username,
                Sid = sid,
                LogonId = logonId
            };
        }

        public static string? ExtractMessageSection(string message, int eventId, int? maxLength = null)
        {
            string? anchor = GetAnchorForEventId(eventId);
            if (string.IsNullOrEmpty(anchor))
                return null;

            return ExtractMessageSection(message, anchor, maxLength, StringComparison.OrdinalIgnoreCase);
        }

        public static int ParseLogonType(string message)
        {
            try
            {
                // "Logon Type:   11"  — appears under "Logon Information:" section
                var match = SafeRegexMatch(message, @"Logon Type:\s*(\d+)", RegexOptions.None);
                if (match.Success && int.TryParse(match.Groups[1].Value, out int lt))
                    return lt;
            }
            catch { /* silent fail */ }
            return 0;
        }

        public static string? GetLogonId(string? message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return null;

            try
            {
                var match = SafeRegexMatch(
                    message,
                    @"Logon ID:\s*(0x[0-9A-Fa-f]+)",
                    RegexOptions.IgnoreCase);

                return match.Success
                    ? match.Groups[1].Value.Trim().ToLowerInvariant()
                    : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Ekstrak Linked Logon ID dari event 4624 admin split-token.
        ///
        /// Windows menulis dua event 4624 untuk setiap admin login (UAC split token):
        ///   - Elevated token  (Elevated Token: Yes)  → punya Linked Logon ID menunjuk ke standard token
        ///   - Standard token  (Elevated Token: No)   → punya Linked Logon ID menunjuk ke elevated token
        ///
        /// Keduanya juga menghasilkan 4634 saat session ditutup:
        ///   - 4634 untuk elevated token session  → LogonId = LogonId dari 4624 elevated
        ///   - 4634 untuk standard token session  → LogonId = LinkedLogonId dari 4624 elevated
        ///
        /// Supaya kedua 4634 bisa diblokir, kita harus register KEDUANYA ke admin
        /// correlation cache:
        ///   - LogonId utama  → dihandle GetLogonId()
        ///   - LinkedLogonId  → dihandle method ini
        ///
        /// Return null jika tidak ditemukan atau nilainya 0x0 (tidak ada linked session).
        /// </summary>
        public static string? GetLinkedLogonId(string? message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return null;

            try
            {
                var match = SafeRegexMatch(
                    message,
                    @"Linked Logon ID:\s*(0x[0-9A-Fa-f]+)",
                    RegexOptions.IgnoreCase);

                if (!match.Success)
                    return null;

                string value = match.Groups[1].Value.Trim().ToLowerInvariant();

                // 0x0 = tidak ada linked session, bukan admin split token
                return Convert.ToInt64(value, 16) != 0 ? value : null;
            }
            catch
            {
                return null;
            }
        }

        public static string? GetUserSidFromSecurityEvent(string message, int securityEventId)
        {
            try
            {
                // Security event only: 4624 (New Logon) and 4647 (Subject).
                string anchor = securityEventId == 4624
                    ? "New Logon:"
                    : (securityEventId == 4634 || securityEventId == 4647)
                        ? "Subject:"
                        : string.Empty;
                if (string.IsNullOrEmpty(anchor))
                    return null;

                int anchorIndex = message.IndexOf(anchor, StringComparison.OrdinalIgnoreCase);
                if (anchorIndex == -1)
                    return null;

                var match = SafeRegexMatch(
                    message,
                    @"Security ID:\s*([^\r\n]+)",
                    RegexOptions.IgnoreCase,
                    anchorIndex);
                if (!match.Success)
                    return null;

                string sid = match.Groups[1].Value.Trim();
                if (string.IsNullOrWhiteSpace(sid) ||
                    sid.Equals("-", StringComparison.OrdinalIgnoreCase) ||
                    sid.Equals("NULL SID", StringComparison.OrdinalIgnoreCase))
                    return null;

                return sid.StartsWith("S-", StringComparison.OrdinalIgnoreCase) ? sid : null;
            }
            catch { /* silent fail */ }

            return null;
        }

        public static string? GetUsernameFromEvent(string message, int eventId)
        {
            try
            {
                if (eventId == 4624)
                {
                    string? section = ExtractMessageSection(message, "New Logon:", comparison: StringComparison.CurrentCulture);
                    if (string.IsNullOrEmpty(section)) return null;

                    var match = SafeRegexMatch(section, @"Account Name:\s*([^\r\n]+)", RegexOptions.None);
                    if (!match.Success) return null;

                    string accountName = match.Groups[1].Value.Trim();
                    if (string.IsNullOrWhiteSpace(accountName) ||
                        accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                        accountName.Equals("-", StringComparison.OrdinalIgnoreCase) ||
                        accountName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        return null;

                    string normalized = NormalizeDisplayUsername(accountName);
                    return IsValidUsername(normalized) ? normalized : null;
                }

                if (eventId == 4634 || eventId == 4647)
                {
                    string? section = ExtractMessageSection(message, "Subject:", comparison: StringComparison.CurrentCulture);
                    if (string.IsNullOrEmpty(section)) return null;

                    var match = SafeRegexMatch(section, @"Account Name:\s*([^\r\n]+)", RegexOptions.None);
                    if (!match.Success) return null;

                    string accountName = match.Groups[1].Value.Trim();
                    if (string.IsNullOrWhiteSpace(accountName) ||
                        accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                        accountName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        return null;

                    string normalized = NormalizeDisplayUsername(accountName);
                    return IsValidUsername(normalized) ? normalized : null;
                }
            }
            catch { /* silent fail */ }

            return null;
        }

        public static string NormalizeDisplayUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return string.Empty;

            string normalized = username.Trim();

            if (normalized.Contains("\\"))
            {
                int slashIndex = normalized.LastIndexOf('\\');
                normalized = normalized.Substring(slashIndex + 1).Trim();
            }

            if (normalized.Contains("@"))
                normalized = normalized.Split('@')[0].Trim();

            // FIX BUG-1: On Azure AD joined devices, 4624 Account Name is UPN prefix
            // (e.g. "nama.panjang") while 4647 and 1074 produce SAMAccountName
            // (e.g. "NamaPanjang"). SID.Translate() always fails on AzureAD → no
            // other canonicalization path exists. Convert dot-separated UPN prefix to
            // TitleCase so all event sources produce an identical username string.
            if (normalized.Contains('.'))
            {
                normalized = string.Concat(
                    normalized.Split('.')
                              .Select(part => part.Length > 0
                                  ? char.ToUpperInvariant(part[0]) + part.Substring(1)
                                  : part));
            }

            return normalized;
        }

        public static bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            if (InvalidUsernames.Contains(username)) return false;
            if (username.EndsWith("$")) return false;

            foreach (var prefix in InvalidUsernamePrefixes)
                if (username.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return false;

            return true;
        }

        private static string? GetAnchorForEventId(int eventId)
        {
            return eventId == 4624 ? "New Logon:" :
                   eventId == 4647 || eventId == 4634 ? "Subject:" : null;
        }

        private static string? ExtractMessageSection(
            string message,
            string anchor,
            int? maxLength = null,
            StringComparison comparison = StringComparison.OrdinalIgnoreCase)
        {
            if (string.IsNullOrEmpty(message))
                return null;

            int index = message.IndexOf(anchor, comparison);
            if (index == -1)
                return null;

            if (maxLength.HasValue)
            {
                int len = Math.Min(maxLength.Value, message.Length - index);
                return message.Substring(index, len);
            }

            return message.Substring(index);
        }

        private static Match SafeRegexMatch(string input, string pattern, RegexOptions options, int? startAt = null)
        {
            try
            {
                if (startAt.HasValue)
                {
                    var regex = new Regex(pattern, options);
                    return regex.Match(input, startAt.Value);
                }
                return Regex.Match(input, pattern, options);
            }
            catch
            {
                return Match.Empty;
            }
        }

        private static int GetNormalizedEventId(EventLogEntry entry)
        {
            return unchecked((int)(entry.InstanceId & 0xFFFF));
        }
    }
}