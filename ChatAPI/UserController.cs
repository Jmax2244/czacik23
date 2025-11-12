using ChatAPI;
using Isopoh.Cryptography.Argon2;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Text;

[ApiController]
[Route("user")]
public class UserController : ControllerBase
{
    private readonly Database _db;

    public UserController()
    {
        _db = new Database(); // używamy Twojego DbContext z OnConfiguring
    }

    [HttpPost("me")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (request == null || string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
            return BadRequest("Email i hasło wymagane");

        var user = _db.Users.FirstOrDefault(u => u.Email == request.Email);
        if (user == null)
            return Unauthorized("Niepoprawny login");

        // Weryfikacja hasła
        if (!VerifyPassword(request.Password, user.PasswordHash))
            return Unauthorized("Niepoprawne hasło");

        // Jeśli wszystko ok, zwracamy token
        var token = "superTajnyToken"; // później możesz podmienić na JWT
        return Ok(new { token });
    }

    private bool VerifyPassword(string password, string storedHash)
    {
        // hash z bazy jest Base64
        byte[] hashBytes = Convert.FromBase64String(storedHash);

        var argon2 = new Argon2i(Encoding.UTF8.GetBytes(password));
        argon2.Salt = new byte[16]; // taka sama sól jak przy generowaniu hash w DB
        var computedHash = argon2.GetBytes(hashBytes.Length);

        return hashBytes.SequenceEqual(computedHash);
    }

}
