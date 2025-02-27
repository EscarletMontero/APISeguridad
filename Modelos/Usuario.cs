using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace GestionDeUsuarioAPI.Modelos
{
    public class Usuario
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [MinLength(2, ErrorMessage = "El nombre debe de tener mas de 2 caractres")]
        public string Nombre { get; set; }
        public string Apellido { get; set; }

        [Required(ErrorMessage = "Este campo es requerido...")]
        [EmailAddress(ErrorMessage ="Debes ingresar un imail valido...")]
        public string Correo { get; set; }

        [Required(ErrorMessage = "Este campo es requerido...")]
        [MinLength(8, ErrorMessage = "La contrasena debe de tener mas de 8 caractres")]
        public string PassWord { get; set; }

        public DateTime FechaDeNacimiento { get; set; }

    }
}
