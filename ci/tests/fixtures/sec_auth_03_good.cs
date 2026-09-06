// SEC-AUTH-03 fixture: nothing here may be reported.
public static class CorrectTokenSetup
{
    public static TokenValidationParameters Build(string issuer, string audience)
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true
        };
    }
}
