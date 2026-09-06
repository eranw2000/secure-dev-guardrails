// Pins ONE hook alternation: ValidateIssuerSigningKey = false alone.
public static class SigningKeyUnchecked
{
    public static TokenValidationParameters Build()
    {
        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = false,
            RequireSignedTokens = true
        };
    }
}
