// Pins ONE case: a claim check switched off, with the signature check left on, so it is the
// second hook pattern and not the first that has to fire.
public static class ClaimsOff
{
    public static TokenValidationParameters Build()
    {
        return new TokenValidationParameters
        {
            ValidateAudience = false,
            RequireSignedTokens = true
        };
    }
}
