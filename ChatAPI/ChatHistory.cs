namespace ChatAPI
{
    public class ChatHistory
    {
        Database db;
        //stara implementacja - lista wiadomości w pamięci
        public List<ChatMessage> Messages { get; set; }

        public ChatHistory(Database db)
        {
            Messages = new List<ChatMessage>();
            this.db = db;
        }
        public void AddMessage(ChatMessage message)
        {
            //Messages.Add(message);
            db.Messages.Add(message);
            //zapisujemy "ręcznie" bo inaczej posty nie trafią do bazy
            db.SaveChanges();
        }
        public List<ChatMessage> GetMessagesAfter(DateTime timestamp)
        {
            //return Messages.Where(m => m.Timestamp > timestamp).ToList();
            return db.Messages.Where(m => m.Timestamp > timestamp).ToList();
        }
        public List<ChatMessage> GetLast(int count)
        {
            //return Messages.TakeLast<ChatMessage>(count).ToList();
            return db.Messages.OrderByDescending(m => m.Timestamp).Take(count).OrderBy(m => m.Timestamp).ToList();
        }
    }
}
