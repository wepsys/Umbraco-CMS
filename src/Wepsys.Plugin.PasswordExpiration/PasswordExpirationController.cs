using System;
using System.Collections.Specialized;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Security;
using Microsoft.AspNet.Identity;
using Umbraco.Core;
using Umbraco.Core.Composing;
using Umbraco.Core.Models;
using Umbraco.Core.Models.Identity;
using Umbraco.Core.Security;
using Umbraco.Web.Models;
using Umbraco.Web.Mvc;
using Umbraco.Web.Security;
using Umbraco.Web.Security.Providers;
using Constants = Umbraco.Core.Constants;
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

            //var viewLocation = ConfigurationManager.AppSettings["Wepsys.Plugin.PasswordExpiration.PasswordChangeViewFullPath"];
            return View("ChangePassword", model);
        }

        public async Task<ActionResult> PostChangePassword([FromBody] ChangingPasswordModel changingPasswordModel)
        {
            changingPasswordModel = changingPasswordModel ?? throw new ArgumentNullException(nameof(changingPasswordModel));

            if (!ModelState.IsValid)
            {
                View("ChangePassword", changingPasswordModel);
            }

            var found = Services.UserService.GetUserById(changingPasswordModel.Id);

            var membersipProvider = new UsersMembershipProvider();
            membersipProvider.Initialize("UsersMembershipProvider", new NameValueCollection());

            var store = new BackOfficeUserStore(Services.UserService, Services.MemberTypeService, Services.EntityService, Services.ExternalLoginService, GlobalSettings, membersipProvider, Current.Mapper);
            var passwordChangeResult = await ChangePasswordWithIdentityAsync(found, found, changingPasswordModel, new BackOfficeUserManager(store));

            if (passwordChangeResult.Success)
            {
                return Redirect("/content");
            }

            return View("ChangePassword", changingPasswordModel);
        }

        private async Task<Attempt<PasswordChangedModel>> ChangePasswordWithIdentityAsync(
            IUser currentUser,
            IUser savingUser,
            ChangingPasswordModel passwordModel,
            BackOfficeUserManager<BackOfficeIdentityUser> userMgr)
        {
            // TODO: Chequear por que el hash no coincide cuando se inicia sesion
            var hash = userMgr.PasswordHasher.HashPassword(passwordModel.NewPassword);

            var user = Current.Mapper.Map(savingUser, new BackOfficeIdentityUser(savingUser.Id, savingUser.Groups));

            user.PasswordHash = hash;

            var result = userMgr.Update(user);

            if (result.Succeeded)
            {
                return Attempt.Succeed(new PasswordChangedModel());
            }

            return Attempt.Fail(new PasswordChangedModel());

            //check if this identity implementation is powered by an underlying membership provider (it will be in most cases)
            var membershipPasswordHasher = userMgr.PasswordHasher as IMembershipProviderPasswordHasher;

            //check if this identity implementation is powered by an IUserAwarePasswordHasher (it will be by default in 7.7+ but not for upgrades)

            if (membershipPasswordHasher != null && !(userMgr.PasswordHasher is IUserAwarePasswordHasher<BackOfficeIdentityUser, int>))
            {
                //if this isn't using an IUserAwarePasswordHasher, then fallback to the old way
                if (membershipPasswordHasher.MembershipProvider.RequiresQuestionAndAnswer)
                    throw new NotSupportedException("Currently the user editor does not support providers that have RequiresQuestionAndAnswer specified");
                return ChangePasswordWithMembershipProvider(savingUser.Username, passwordModel, membershipPasswordHasher.MembershipProvider);
            }

            //if we are here, then a IUserAwarePasswordHasher is available, however we cannot proceed in that case if for some odd reason
            //the user has configured the membership provider to not be hashed. This will actually never occur because the BackOfficeUserManager
            //will throw if it's not hashed, but we should make sure to check anyways (i.e. in case we want to unit test!)
            if (membershipPasswordHasher != null && membershipPasswordHasher.MembershipProvider.PasswordFormat != MembershipPasswordFormat.Hashed)
            {
                throw new InvalidOperationException("The membership provider cannot have a password format of " + membershipPasswordHasher.MembershipProvider.PasswordFormat + " and be configured with secured hashed passwords");
            }

            //Are we resetting the password?
            //This flag indicates that either an admin user is changing another user's password without knowing the original password
            // or that the password needs to be reset to an auto-generated one.
            if (passwordModel.Reset.HasValue && passwordModel.Reset.Value)
            {
                //if it's the current user, the current user cannot reset their own password
                if (currentUser.Username == savingUser.Username)
                {
                    return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Password reset is not allowed", new[] { "resetPassword" }) });
                }

                //if the current user has access to reset/manually change the password
                if (currentUser.HasSectionAccess(Constants.Applications.Users) == false)
                {
                    return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("The current user is not authorized", new[] { "resetPassword" }) });
                }

                //ok, we should be able to reset it
                var resetToken = await userMgr.GeneratePasswordResetTokenAsync(savingUser.Id);
                var newPass = passwordModel.NewPassword.IsNullOrWhiteSpace()
                    ? userMgr.GeneratePassword()
                    : passwordModel.NewPassword;

                var resetResult = await userMgr.ChangePasswordWithResetAsync(savingUser.Id, resetToken, newPass);

                if (resetResult.Succeeded == false)
                {
                    var errors = string.Join(". ", resetResult.Errors);
                    Current.Logger.Warn(this.GetType(), "Could not reset user password {PasswordErrors}", errors);
                    return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult(errors, new[] { "resetPassword" }) });
                }

                return Attempt.Succeed(new PasswordChangedModel());
            }

            //we're not resetting it so we need to try to change it.

            if (passwordModel.NewPassword.IsNullOrWhiteSpace())
            {
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Cannot set an empty password", new[] { "value" }) });
            }

            //we cannot arbitrarily change the password without knowing the old one and no old password was supplied - need to return an error
            if (passwordModel.OldPassword.IsNullOrWhiteSpace())
            {
                //if password retrieval is not enabled but there is no old password we cannot continue
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Password cannot be changed without the old password", new[] { "oldPassword" }) });
            }

            //get the user
            var backOfficeIdentityUser = await userMgr.FindByIdAsync(savingUser.Id);
            if (backOfficeIdentityUser == null)
            {
                //this really shouldn't ever happen... but just in case
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Password could not be verified", new[] { "oldPassword" }) });
            }
            //can we change to the new password?


            var changeResult = await userMgr.ChangePasswordAsync(savingUser.Id, passwordModel.OldPassword, passwordModel.NewPassword);
            if (changeResult.Succeeded == false)
            {
                //no, fail with error messages for "password"
                var errors = string.Join(". ", changeResult.Errors);
                Current.Logger.Warn(this.GetType(), "Could not change user password {PasswordErrors}", errors);
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult(errors, new[] { "password" }) });
            }
            return Attempt.Succeed(new PasswordChangedModel());
        }

        private Attempt<PasswordChangedModel> ChangePasswordWithMembershipProvider(string username, ChangingPasswordModel passwordModel, MembershipProvider membershipProvider)
        {
            var umbracoBaseProvider = membershipProvider as MembershipProviderBase;

            // YES! It is completely insane how many options you have to take into account based on the membership provider. yikes!

            if (passwordModel == null) throw new ArgumentNullException(nameof(passwordModel));
            if (membershipProvider == null) throw new ArgumentNullException(nameof(membershipProvider));

            BackOfficeUserManager<BackOfficeIdentityUser> backofficeUserManager = null;
            var userId = -1;

            if (membershipProvider.IsUmbracoUsersProvider())
            {
                backofficeUserManager = Current.Factory.TryGetInstance<BackOfficeUserManager<BackOfficeIdentityUser>>();
                if (backofficeUserManager != null)
                {
                    var profile = Services.UserService.GetProfileByUserName(username);
                    if (profile != null)
                        int.TryParse(profile.Id.ToString(), out userId);
                }
            }

            //Are we resetting the password?
            //This flag indicates that either an admin user is changing another user's password without knowing the original password
            // or that the password needs to be reset to an auto-generated one.
            if (passwordModel.Reset.HasValue && passwordModel.Reset.Value)
            {
                //if a new password is supplied then it's an admin user trying to change another user's password without knowing the original password
                //this is only possible when using a membership provider if the membership provider supports AllowManuallyChangingPassword
                if (passwordModel.NewPassword.IsNullOrWhiteSpace() == false)
                {
                    if (umbracoBaseProvider != null && umbracoBaseProvider.AllowManuallyChangingPassword)
                    {
                        //this provider allows manually changing the password without the old password, so we can just do it
                        try
                        {
                            var result = umbracoBaseProvider.ChangePassword(username, string.Empty, passwordModel.NewPassword);

                            return result == false
                                ? Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Could not change password, invalid username or password", new[] { "value" }) })
                                : Attempt.Succeed(new PasswordChangedModel());
                        }
                        catch (Exception ex)
                        {
                            Current.Logger.Warn(this.GetType(), "Could not reset user password {PasswordErrors}", ex);
                            return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Could not change password, error: " + ex.Message + " (see log for full details)", new[] { "value" }) });
                        }
                    }
                    else
                    {
                        return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Provider does not support manually changing passwords", new[] { "value" }) });
                    }
                }

                try
                {
                    var newPass = membershipProvider.ResetPassword(
                            username,
                            membershipProvider.RequiresQuestionAndAnswer ? passwordModel.Answer : null);

                    //return the generated pword
                    return Attempt.Succeed(new PasswordChangedModel { ResetPassword = newPass });
                }
                catch (Exception ex)
                {
                    Current.Logger.Warn(this.GetType(), "Could not reset user password {PasswordErrors}", ex);
                    return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Could not reset password, error: " + ex.Message + " (see log for full details)", new[] { "resetPassword" }) });
                }
            }

            //we're not resetting it so we need to try to change it.

            if (passwordModel.NewPassword.IsNullOrWhiteSpace())
            {
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Cannot set an empty password", new[] { "value" }) });
            }

            //without being able to retrieve the original password, 
            //we cannot arbitrarily change the password without knowing the old one and no old password was supplied - need to return an error
            if (passwordModel.OldPassword.IsNullOrWhiteSpace() && membershipProvider.EnablePasswordRetrieval == false)
            {
                //if password retrieval is not enabled but there is no old password we cannot continue
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Password cannot be changed without the old password", new[] { "oldPassword" }) });
            }

            if (passwordModel.OldPassword.IsNullOrWhiteSpace() == false)
            {
                //if an old password is supplied try to change it

                try
                {
                    var result = membershipProvider.ChangePassword(username, passwordModel.OldPassword, passwordModel.NewPassword);
                    
                    return result == false
                        ? Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Could not change password, invalid username or password", new[] { "oldPassword" }) })
                        : Attempt.Succeed(new PasswordChangedModel());
                }
                catch (Exception ex)
                {
                    Current.Logger.Warn(this.GetType(), "Could not change user password {PasswordErrors}", ex);
                    return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Could not change password, error: " + ex.Message + " (see log for full details)", new[] { "value" }) });
                }
            }

            if (membershipProvider.EnablePasswordRetrieval == false)
            {
                //we cannot continue if we cannot get the current password
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Password cannot be changed without the old password", new[] { "oldPassword" }) });
            }
            if (membershipProvider.RequiresQuestionAndAnswer && passwordModel.Answer.IsNullOrWhiteSpace())
            {
                //if the question answer is required but there isn't one, we cannot continue
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Password cannot be changed without the password answer", new[] { "value" }) });
            }

            //lets try to get the old one so we can change it
            try
            {
                var oldPassword = membershipProvider.GetPassword(
                    username,
                    membershipProvider.RequiresQuestionAndAnswer ? passwordModel.Answer : null);

                try
                {
                    var result = membershipProvider.ChangePassword(username, oldPassword, passwordModel.NewPassword);
                    return result == false
                        ? Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Could not change password", new[] { "value" }) })
                        : Attempt.Succeed(new PasswordChangedModel());
                }
                catch (Exception ex1)
                {
                    Current.Logger.Warn(this.GetType(), "Could not change user password {PasswordErrors}", ex1);
                    return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Could not change password, error: " + ex1.Message + " (see log for full details)", new[] { "value" }) });
                }

            }
            catch (Exception ex2)
            {
                Current.Logger.Warn(this.GetType(), "Could not retrieve user password {PasswordErrors}", ex2);
                return Attempt.Fail(new PasswordChangedModel { ChangeError = new ValidationResult("Could not change password, error: " + ex2.Message + " (see log for full details)", new[] { "value" }) });
            }
        }
    }
}
