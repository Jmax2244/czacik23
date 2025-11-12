using ChatAPI;
using System.Web;

var builder = WebApplication.CreateBuilder(args);
//dodaj baze danych do aplikacji
builder.Services.AddDbContext<Database>();


var app = builder.Build();
app.UseBearerMiddleware(); //to jest jeden sposób - ten bardziej poprawny
//app.UseMiddleware<BearerMiddleware>(); //to jest drugi sposób - oba dzia³aj¹
//ustaw adresy ip i porty
app.Urls.Add("http://0.0.0.0:5000");
app.UseRouting();

//TODO: do wywalenia po zintegrowaniu z baz¹ danych
//ChatHistory chatHistory = new ChatHistory();
//chatHistory.AddMessage(new ChatMessage("User", "Hello!"));
//chatHistory.AddMessage(new ChatMessage("Bot", "Hi there! How can I assist you today?"));
//chatHistory.AddMessage(new ChatMessage("User", "Can you tell me a joke?"));


app.MapGet("/", () => "Hello World!");

//logowanie u¿ytkownika
app.MapPost("/user/me", (Database db, User user) =>
{
    //w prawdziwej apce tutaj byœmy sprawdzali usera i has³o
    return Results.Ok();
});
//rejestracja u¿ytkownika
app.MapPost("/users", (Database db, User user) =>
{
    db.Users.Add(user);
    db.SaveChanges();
    return Results.Created($"{user.Id}", user);
});
//pobranie historii czatu
app.MapGet("/chat/messages", (Database db, string minimalDate) =>
{
    ChatHistory chatHistory = new ChatHistory(db);
    //tutaj zwracamy historiê czatu
    //ustawiamy defaultowy czas ostatniej wiadomoœci na teraz
    //nie jest to zbyt logiczne ale potrzebujemy pocz¹tkowej wartoœci
    DateTime parsedTimestamp = DateTime.Now;
    //timestamp jest w postaci stringa "2025-10-13T13:08:22.1712280+02:00"
    //parsujemy go do formatu obiektu datetime
    DateTime.TryParse(minimalDate, out parsedTimestamp);
    //odpytujemy nasz¹ klasê o wiadomoœci po danym timestampie i wysy³amy
    return chatHistory.GetMessagesAfter(parsedTimestamp);
});
//dodanie wiadomoœci do czatu
app.MapPost("/chat/messages", (Database db, ChatMessage message) =>
{
    if(string.IsNullOrEmpty(message.Content) || string.IsNullOrEmpty(message.Author))
    {
        return Results.BadRequest("Author and Content fields are required.");
    }
    ChatHistory chatHistory = new ChatHistory(db);
    chatHistory.AddMessage(message);
    return Results.Created($"/chat/messages/{message.Timestamp.Ticks}", message);
});
app.Run();
