using BaseLibrary.DTOs;
using BaseLibrary.Entites;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ServerLibrary.Repositories.Implementaions
{
    public class UserAccountRepostiory(IOptions<JwtSection> config, AppDbContext appDbContext) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if(user is null)
            {
                return new GeneralResponse(false, "Model is empty");
            }

            var CheckUser = await FindUserByEmail(user.Email);

            if(CheckUser != null)
            {
                return new GeneralResponse(false, "User already exist");
            }

            // Save user
            var appUser = await AddToDatabase(new AppUser()
            {
                FullName = user.FullName,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });


            // Check,Create and assign role

            var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_=>_.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var  createAdminRole = await AddToDatabase(new SystemRoles() { Name = Constants.Admin });
                await AddToDatabase(new UserRole() { UserId = appUser.Id, RoleId = createAdminRole.Id });
                return new GeneralResponse(true, "Account created successfully");

            }

            var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_=>_.Name!.Equals(Constants.User));
            if (checkUserRole is null)
            {
                var createUserRole = await AddToDatabase(new SystemRoles() { Name = Constants.User });
                await AddToDatabase(new UserRole() { UserId = appUser.Id, RoleId = createUserRole.Id });
            }
            else
            {
                await AddToDatabase(new UserRole() { UserId = appUser.Id, RoleId = checkAdminRole.Id });
            }
            return new GeneralResponse(true, "Account created successfully");

        }

        public async Task<LoginResponse> SignInAsync(Login user)
        {
            if (user is null)
            {
                return new LoginResponse(false, "Model is empty");
            }

            var AppUser = await FindUserByEmail(user.Email!);
            if (AppUser is null)
            {
                return new LoginResponse(false, "User not found");
            }

            // Check password
            if (!BCrypt.Net.BCrypt.Verify(user.Password, AppUser.Password))
            {
                return new LoginResponse(false, "Invalid Email/password");
            }

            var getUserRole = await FindUserRole(AppUser.Id);
            if (getUserRole is null)
            {
                return new LoginResponse(false, "User role not found");
            }

            var getRoleName = await FindRoleName(getUserRole.RoleId);
            if (getRoleName is null)
            {
                return new LoginResponse(false, "Role not found");
            }

            // Generate token

            string jwtToken = GenerateToken(AppUser, getRoleName!.Name!);
            string refreshToken = GenerateRefreshToken();

            // Save refresh token to database
            var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_=>_.UserId == AppUser.Id);
            if (findUser is not null)
            {
                findUser.Token = refreshToken;
                await appDbContext.SaveChangesAsync();
            }
            else
            {
                await AddToDatabase(new RefreshTokenInfo() { Token = refreshToken, UserId = AppUser.Id });
            }

            return new LoginResponse(true, "Login successful", jwtToken, refreshToken);
        }

        private string GenerateToken(AppUser user, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()!),
                new Claim(ClaimTypes.Name, user.FullName!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, role!)
            };

            var token = new JwtSecurityToken(
                issuer:config.Value.Issuer,
                audience:config.Value.Audience,
                claims:userClaims,
                expires: DateTime.Now.AddDays(10),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<UserRole> FindUserRole(int userId) => await appDbContext.UserRoles.FirstOrDefaultAsync(_=>_.UserId == userId);

        private async Task<SystemRoles> FindRoleName(int roleId) => await appDbContext.SystemRoles.FirstOrDefaultAsync(_=>_.Id == roleId);

        private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        

        private async Task<AppUser> FindUserByEmail(string email)=> 
            await appDbContext.AppUsers.FirstOrDefaultAsync(_=>_.Email!.ToLower()!.Equals(email!.ToLower()));


        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = await appDbContext.AddAsync(model!);
            await appDbContext.SaveChangesAsync();
            return (T)result.Entity;
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            if (token is null)
            {
                return new LoginResponse(false, "Model is empty");
            }

            var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_=>_.Token!.Equals(token.Token));
            if (findToken is null)
            {
                return new LoginResponse(false, "Refresh token is required");
            }

            //get user details

            var User = await appDbContext.AppUsers.FirstOrDefaultAsync(_=>_.Id == findToken.UserId);
            if (User is null)
            {
                return new LoginResponse(false, "Refresh token could not generated becouse User not found");
            }

            var userRole = await FindUserRole(User.Id);
            var roleName = await FindRoleName(userRole.RoleId);
            string jwtToken = GenerateToken(User, roleName.Name!);
            string refreshToken = GenerateRefreshToken();

            var updateRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_=>_.UserId == User.Id);
            if (updateRefreshToken is null)
            {
                return new LoginResponse(false, "Refresh token could not generated becouse User has not signed in");
            }

            updateRefreshToken.Token = refreshToken;
            await appDbContext.SaveChangesAsync();
            return new LoginResponse(true, "Token refreshed successfully", jwtToken, refreshToken);
        }
    }
}
