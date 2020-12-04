using System.Collections.Generic;
using Wepsys.Plugin.PasswordExpiration.Enums;

namespace Wepsys.Plugin.PasswordExpiration.Helpers
{
    class PasswordValidityErrorMessages
    {
        internal static Dictionary<PasswordValidityError, string> ErrorMessages { get; set; } = new Dictionary<PasswordValidityError, string>
        {
            { PasswordValidityError.Length, "Su nueva contraseña debe tener al menos {0} o más caracteres." },
            { PasswordValidityError.Strength, "Su nueva contraseña es muy débil, ingrese al menos una letra mayúscula y un número." },
            { PasswordValidityError.AlphanumericChars, "Su nueva contraseña debe contener al menos {0} o más caracteres no alfanuméricos." }
        };
    }
}
