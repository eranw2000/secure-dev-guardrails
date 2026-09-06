// Pins ONE hook alternation: the built-in signature check replaced by a delegate. This one hands
// back the token unverified, which is the shape that ships as "custom validation".
public static class ReplacedSignatureCheck
{
    public static TokenValidationParameters Build()
    {
        return new TokenValidationParameters
        {
            SignatureValidator = (token, parameters) => new JwtSecurityToken(token)
        };
    }
}
