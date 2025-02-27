using Microsoft.EntityFrameworkCore;
using GestionDeUsuarioAPI.Modelos;
 
namespace GestionDeUsuarioAPI.DB
{
    public class ContextDB : DbContext
    {
        public ContextDB(DbContextOptions options): base(options) 
        {
            
        }
        public DbSet<Usuario> Usuarios { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Usuario>()
                .HasIndex(u => u.Correo)
                .IsUnique(); // Evita emails duplicados
        }
    }
}
