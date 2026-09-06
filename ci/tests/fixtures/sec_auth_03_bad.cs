// SEC-AUTH-03 fixture: the hook MUST report this file.
// semgrep ships no C# rule for SEC-AUTH-03, so C# is exactly the case the shell hook is
// carrying on its own, and it is the language where the switches are most explicit.
public static class BrokenTokenSetup
{
    public static TokenValidationParameters Build()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = false
        };
    }
}
