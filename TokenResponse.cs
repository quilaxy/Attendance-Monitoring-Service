namespace EventLogOutEmployeeService;

public class TokenResponse
{
    public string? access_token { get; set; }

    /// <summary>
    /// Token lifetime in seconds, as returned by Azure AD. Normally 3600, but can
    /// differ if a Custom Token Lifetime policy is configured on the tenant.
    /// Nullable because older/alternate token endpoints may omit this field.
    /// </summary>
    public int? expires_in { get; set; }
}