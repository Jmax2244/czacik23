using Isopoh.Cryptography.Argon2;
namespace ChatAPI
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        
        public User(string email, string passwordHash)
        {
            //unikatowy identyfikator
            Id = Guid.NewGuid().GetHashCode();
            //login i adres email w jednym
            Email = email;
            //password hash argon2i z password
            PasswordHash = passwordHash;
        }
    }
}
