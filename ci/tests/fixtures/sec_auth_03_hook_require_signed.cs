// Pins ONE hook alternation: RequireSignedTokens = false alone, every claim check left on.
public static class UnsignedAllowed
{
    public static TokenValidationParameters Build()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireSignedTokens = false
        };
    }
}
