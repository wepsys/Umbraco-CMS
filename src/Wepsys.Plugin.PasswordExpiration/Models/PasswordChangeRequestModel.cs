using System.ComponentModel.DataAnnotations;

namespace Wepsys.Plugin.PasswordExpiration.Models
{
    public class PasswordChangeRequestModel
    {
        /// <summary>
        /// The id of the user - required to allow changing password without the entire UserSave model
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// The password value
        /// </summary>
        [Required(ErrorMessage = "El campo nueva contraseña es requerido.")]
        public string NewPassword { get; set; }

        /// <summary>
        /// The password value
        /// </summary>
        [Required(ErrorMessage = "El campo nueva contraseña es requerido")]
        [Compare("NewPassword", ErrorMessage = "La nueva contraseña no coincide con la confirmación de la misma.")]
        public string ConfirmPassword { get; set; }

        /// <summary>
        /// The old password that will replace the current password
        /// </summary>
        [Required(ErrorMessage = "El campo antigua contraseña es requerido.")]
        public string OldPassword { get; set; }
    }
}
