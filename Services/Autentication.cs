using Azure.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class Autenticacion : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly string _key;
    private readonly IConfiguration _config;
    private readonly ILogger<Autenticacion> _logger;

    public Autenticacion(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder, ISystemClock clock, IConfiguration config)
        : base(options, logger, encoder, clock)
    {
        _config = config;
        _key = _config["JwtSettings:SecretKey"];
        _logger = logger.CreateLogger<Autenticacion>(); 
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var token = ObtenerTokenDesdeEncabezado();
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Token no encontrado o formato incorrecto.");
                return AuthenticateResult.Fail("Token no encontrado o formato incorrecto");
            }

            var principal = ValidarToken(token);
            if (principal == null)
            {
                _logger.LogWarning("Token invalido.");
                return AuthenticateResult.Fail("Token invalido");
            }

            var ticket = new AuthenticationTicket(principal, "JwtCustomScheme");
            return AuthenticateResult.Success(ticket);
        }
        catch (SecurityTokenExpiredException)
        {
            _logger.LogError("El token ha expirado.");
            return AuthenticateResult.Fail("Token expirado");
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogError($"Error de validacion del token: {ex.Message}");
            return AuthenticateResult.Fail($"Error de validacion del token: {ex.Message}");
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error de autenticacion: {ex.Message}");
            return AuthenticateResult.Fail($"Error de autenticacion: {ex.Message}");
        }
    }

    private string ObtenerTokenDesdeEncabezado()
    {
        var authHeader = Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            return null;
        }
        return authHeader.Substring("Bearer ".Length).Trim();
    }
    private ClaimsPrincipal ValidarToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_key);

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            var principal = tokenHandler.ValidateToken(token, validationParams, out SecurityToken validatedToken);

            // Verifico si el token tiene los claims esperados
            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var userName = principal.FindFirst(ClaimTypes.Name)?.Value;

            if (userId == null || userName == null)
            {
                _logger.LogError("El token no contiene los claims esperados.");
                return null;
            }

            _logger.LogInformation($"Token valido. UserId: {userId}, UserName: {userName}");
            return principal;
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogError($" Error de validacion del token: {ex.Message}");
            return null;
        }
    }
}
