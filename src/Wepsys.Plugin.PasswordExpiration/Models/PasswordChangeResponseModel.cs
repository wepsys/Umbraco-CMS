using System.Collections.Generic;

namespace Wepsys.Plugin.PasswordExpiration.Models
{
    public class PasswordChangeResponseModel
    {
        public string SuccessRedirectUrl { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }
}
