using GestionDeUsuarioAPI.Services.UsuariosServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using GestionDeUsuarioAPI.Modelos;

namespace GestionDeUsuarioAPI.Controllers
{
    [Route("api/Adm")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUsuarioService _usuarioService;
        private readonly IConfiguration _config;

        public AuthController(IUsuarioService usuarioService, IConfiguration config)
        {
            _usuarioService = usuarioService;
            _config = config;
        }

        //  Esta para autenticar usuarios y crear el token
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var token = await _usuarioService.AuthUser(loginModel.Correo, loginModel.PassWord);

            if (token == "Credenciales incorrectas.")
            {
                return Unauthorized(new { message = "Correo o contraseña incorrectos" });
            }

            return Ok(new { message = "Autenticacion exitosa", token });
        }
        private string GenerateJwtToken(string userId, string userName)
        {
            var key = Encoding.UTF8.GetBytes(_config["JwtSettings:SecretKey"]);
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Name, userName)
        }),
                Expires = DateTime.UtcNow.AddMinutes(5), 
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _config["JwtSettings:Issuer"],
                Audience = _config["JwtSettings:Audience"]
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


        // Refresca el token existente 
        [HttpPost("refresh")]
        public IActionResult RefreshToken()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var userName = User.FindFirst(ClaimTypes.Name)?.Value;

            if (userId == null || userName == null)
            {
                Console.WriteLine(" No se pudo extraer el usuario del token.");
                return Unauthorized(new { message = "No se pudo refrescar el token" });
            }

            Console.WriteLine($"Usuario ya esta autenticado: {userName} (ID: {userId})");

            var newToken = GenerateJwtToken(userId, userName);

            return Ok(new { token = newToken });
        }
    }
}
