using Microsoft.EntityFrameworkCore;

namespace ChatAPI
{
    public class Database : DbContext
    {
        //zestaw danych - obiekty klasy ChatMessage
        public DbSet<ChatMessage> Messages { get; set; }
        //użytkownicy
        public DbSet<User> Users { get; set; }

        //przeciążamy metodę konfigurującą bazę danych aby ustawić ją na SQLite
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            //ustawiamy bazę danych na SQLite
            optionsBuilder.UseSqlite("Data Source=chat.db");
        }
        //przeciążamy metodę konfigurującą model danych
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //zapisuj wiadomości w tabeli o nazwie "Messages"
            modelBuilder.Entity<ChatMessage>().ToTable("Messages");
            //ustal klucz główny na pole Timestamp
            modelBuilder.Entity<ChatMessage>().HasKey(m => m.Timestamp);
            //ustalamy wymagane pola
            modelBuilder.Entity<ChatMessage>().Property(m => m.Author).IsRequired();
            modelBuilder.Entity<ChatMessage>().Property(m => m.Content).IsRequired();

            //zapisuj użytkowników w tabeli o nazwie "Users"
            modelBuilder.Entity<User>().ToTable("Users");
            //ustal klucz główny na pole Id
            modelBuilder.Entity<User>().HasKey(u => u.Id);
            //ustalamy wymagane pola
            modelBuilder.Entity<User>().Property(u => u.Email).IsRequired();
            modelBuilder.Entity<User>().Property(u => u.PasswordHash).IsRequired();
        }
    }
}
