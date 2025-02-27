using GestionDeUsuarioAPI.DB;
using GestionDeUsuarioAPI.Modelos;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace GestionDeUsuarioAPI.Services.UsuariosServices
{
    public class UsuarioService : IUsuarioService
    {
        private readonly ContextDB _context;
        private readonly string _secretKey;

        public UsuarioService(ContextDB context, IConfiguration config)
        {
            _context = context;
            _secretKey = config["JwtSettings:SecretKey"];
        }

        public async Task<string> AuthUser(string correo, string password)
        {
            var usuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.Correo == correo);
            if (usuario == null || !BCrypt.Net.BCrypt.Verify(password, usuario.PassWord))
            {
                return "Credenciales incorrectas.";
            }

            return GenerateJwtToken(usuario);
        }

        private string GenerateJwtToken(Usuario usuario)
        {
            var key = Encoding.UTF8.GetBytes(_secretKey);
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
                    new Claim(ClaimTypes.Name, usuario.Nombre)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
