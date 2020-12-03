using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel.DataAnnotations;
using System.Configuration;
using System.Linq;
using System.Net.Mime;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Umbraco.Core;
using Umbraco.Core.Composing;
using Umbraco.Core.Models.Identity;
using Umbraco.Core.Security;
using Umbraco.Web.Models;
using Umbraco.Web.Mvc;
using Umbraco.Web.Security;
using Umbraco.Web.Security.Providers;
using Wepsys.Plugin.PasswordExpiration.Enums;
using Wepsys.Plugin.PasswordExpiration.Helpers;
using Wepsys.Plugin.PasswordExpiration.Models;
using IUser = Umbraco.Core.Models.Membership.IUser;

namespace Wepsys.Plugin.PasswordExpiration
{
    public class PasswordExpirationController : RenderMvcController
    {
        public ActionResult ChangePassword(int userId)
        {
            var model = new ChangingPasswordModel
            {
                Id = userId
            };

            var viewLocation = ConfigurationManager.AppSettings["Wepsys.Plugin.PasswordExpiration.PasswordChangeViewFullPath"];
            return View(viewLocation, model);
        }

        public async Task<JsonResult> PostChangePassword([FromBody] PasswordChangeRequestModel changingPasswordModel)
        {
            var result = new PasswordChangeResponseModel();

            if (!ModelState.IsValid)
            {
                foreach (var modelState in ModelState.Values)
                {
                    var errors = modelState.Errors
                        .Where(err => !string.IsNullOrWhiteSpace(err.ErrorMessage))
                        .Select(error => error.ErrorMessage);

                    result.Errors.AddRange(errors);
                }

                return Json(result, "application/json");
            }

            var found = Services.UserService.GetUserById(changingPasswordModel.Id);

            var membersipProvider = new UsersMembershipProvider();
            membersipProvider.Initialize("UsersMembershipProvider", new NameValueCollection());

            var store = new BackOfficeUserStore(Services.UserService, Services.MemberTypeService,
                Services.EntityService, Services.ExternalLoginService, GlobalSettings, membersipProvider,
                Current.Mapper);

            var manager = new BackOfficeUserManager(store)
            {
                PasswordHasher = new UserAwareMembershipProviderPasswordHasher(membersipProvider)
            };

            var oldPasswordVerificationResult = manager.PasswordHasher.VerifyHashedPassword(found.RawPasswordValue, changingPasswordModel.OldPassword);

            if (oldPasswordVerificationResult == PasswordVerificationResult.Failed)
            {
                result.Errors.Add("La contraseña antigua es incorrecta.");

                return Json(result, "application/json");
            }

            int minAlpanumeric = membersipProvider.MinRequiredNonAlphanumericCharacters;
            int minPasswordLength = membersipProvider.MinRequiredPasswordLength;

            var newPasswordVerificationResult = IsPasswordValid(changingPasswordModel.NewPassword,
                minAlpanumeric == 0 ? membersipProvider.DefaultMinNonAlphanumericChars : minAlpanumeric,
                membersipProvider.PasswordStrengthRegularExpression,
                minPasswordLength == 0 ? membersipProvider.DefaultMinPasswordLength : minPasswordLength);

            if (!newPasswordVerificationResult.Success)
            {
                result.Errors.Add(newPasswordVerificationResult.Result);

                return Json(result, "application/json");
            }

            var passwordChangeResult =
                await ChangePasswordWithIdentityAsync(found, changingPasswordModel, manager);

            if (passwordChangeResult.Success)
            {
                result.SuccessRedirectUrl = "/content";

                return Json(result, "application/json");
            }

            result.Errors.AddRange(passwordChangeResult.Result.Errors);

            return Json(result, "application/json");
        }

        private async Task<Attempt<PasswordChangeResponseModel>> ChangePasswordWithIdentityAsync(
            IUser savingUser,
            PasswordChangeRequestModel passwordModel,
            BackOfficeUserManager<BackOfficeIdentityUser> userMgr)
        {
            var changeResult = await userMgr.ChangePasswordAsync(savingUser.Id, passwordModel.OldPassword, passwordModel.NewPassword);

            if (changeResult.Succeeded)
                return Attempt.Succeed(new PasswordChangeResponseModel());

            return Attempt.Fail(new PasswordChangeResponseModel { Errors = changeResult.Errors.Select(error => $" Hubo un error cambiando la contraseña: {error}").ToList() });
        }

        private Attempt<string> IsPasswordValid(string password, int minRequiredNonAlphanumericChars, string strengthRegex, int minLength)
        {
            if (minRequiredNonAlphanumericChars > 0)
            {
                var nonAlphaNumeric = Regex.Replace(password, "[a-zA-Z0-9]", "", RegexOptions.Multiline | RegexOptions.IgnoreCase);
                if (nonAlphaNumeric.Length < minRequiredNonAlphanumericChars)
                {
                    var errorMessage = PasswordValidityErrorMessages.ErrorMessages[PasswordValidityError.AlphanumericChars];

                    return Attempt.Fail(string.Format(errorMessage, minRequiredNonAlphanumericChars));
                }
            }

            if (!string.IsNullOrEmpty(strengthRegex))
            {
                if (!Regex.IsMatch(password, strengthRegex, RegexOptions.Compiled))
                {
                    return Attempt.Fail(PasswordValidityErrorMessages.ErrorMessages[PasswordValidityError.Strength]);
                }

            }

            if (password.Length < minLength)
            {
                var errorMessage = PasswordValidityErrorMessages.ErrorMessages[PasswordValidityError.Length];

                return Attempt.Fail(string.Format(errorMessage, minLength));
            }

            return Attempt.Succeed(string.Empty);
        }
    }
}
