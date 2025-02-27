using GestionDeUsuarioAPI.Modelos;

namespace GestionDeUsuarioAPI.Services.UsuariosServices
{
    public interface IUsuarioService
    {
        // Metodo para mi autenticacion y crear el token
        Task<string> AuthUser(string correo, string password);  
    }
}