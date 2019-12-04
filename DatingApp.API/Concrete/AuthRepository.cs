using DatingApp.API.Data;
using DatingApp.API.Infrastructure;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DatingApp.API.Concrete
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _dataContext;
        public AuthRepository(DataContext dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<User> Login(string username, string password)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(item => item.UserName == username);

            if (user == null)
                return null;

            if (!VerifyPasswordHash(user, password))
                return null;

            return user;

        }

        private bool VerifyPasswordHash(User user, string password)
        {
            using var hmac = new HMACSHA512(user.PasswodSalt);
            var passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

            for (int i = 0; i < user.PasswordHash.Length; i++)
            {
                if (user.PasswordHash[i] != passwordHash[i])
                    return false;
            }

            return true;
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwordHash, passwordSalt;
            CreatePasswordHash(password, out passwordHash, out passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswodSalt = passwordSalt;

            await _dataContext.AddAsync(user);
            await _dataContext.SaveChangesAsync();

            return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        public async Task<bool> UserExists(string userName)
        {
            return await _dataContext.Users.AnyAsync(item => item.UserName == userName);
        }
    }
}
