using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace ChatAPI
{
    public class BearerMiddleware
    {
        //odwołanie od następnego middleware w potoku
        private readonly RequestDelegate _next;

        //konstruktor do naszego middleware
        //przyjmuje odwołanie do następnego middleware
        //zapiszemy je sobie w polu _next
        public BearerMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        //to jest faktyczna metoda która będzie wywoływana
        public async Task InvokeAsync(HttpContext context)
        {
            //pomiń middleware dla endpointu rejestracji i logowania
            if (context.Request.Path.Equals("/users") || context.Request.Path.Equals("/user/me"))
            {
                await _next(context);
                return;
            }
            //pobierz sobie nagłówek do stringa
            string authHeader = context.Request.Headers["Authorization"].ToString();
            //teraz może być tak, że authHeader jest pusty lub nie zawiera "Bearer "
            //jeżeli pole authHeader jest puste lub nie zaczyna się od "Bearer "
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                //jeśli tak to zwróć 401 Unauthorized
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Unauthorized: Missing or invalid Authorization header.");
                return; //uwaga tutaj apka kończy działanie - nie przejdzie do następnego middleware
            }
            //jesli dotarlismy tutaj to znaczy że mamy nagłówek i zaczyna się od Bearer
            //obcinamy sobie początek "Bearer " i zostawiamy sam token
            string token = authHeader.Substring("Bearer ".Length).Trim();
            //sprawdzmy sobie tylko czy token jest równy jakiemuś przykładowemu tokenowi
            if(token != "superTajnyToken")
            {
                //jeśli token jest nieprawidłowy to zwróć 403 Forbidden
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("Forbidden: Invalid token.");
                return; //uwaga tutaj apka kończy działanie - nie przejdzie do następnego middleware
            }
            //jeśli dotarliśmy tutaj to znaczy że mamy prawidłowy token
            //przekazujemy kontrolę do następnego middleware w potoku
            await _next(context);
        }
    }
}
