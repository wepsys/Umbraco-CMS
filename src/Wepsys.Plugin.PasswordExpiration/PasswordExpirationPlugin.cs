using System.Web.Mvc;
using System.Web.Routing;
using Umbraco.Core.Composing;
using Umbraco.Web;

namespace Wepsys.Plugin.PasswordExpiration
{
    public class PasswordExpirationPlugin : IComposer
    {
        public void Compose(Composition composition)
        {
            RouteTable.Routes.MapRoute(
                name: "ChangePassword",
                url: "umbraco/backoffice/PasswordExpiration/ChangePassword/{userId}",
                defaults: new { controller = "PasswordExpiration", action = "ChangePassword" }
            );

            RouteTable.Routes.MapRoute(
                name: "PostChangeExpiredPassword",
                url: "umbraco/backoffice/PasswordExpiration/PostChangePassword",
                defaults: new { controller = "PasswordExpiration", action = "PostChangePassword" }
            );

            composition.SetDefaultRenderMvcController<PasswordExpirationController>();
        }
    }
}
