import { Database } from "bun:sqlite";

type userRow = {
  username: string;
  password_hash: string;
}

export class DB {
  db = new Database("db.sqlite");

  constructor() {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS user_hashes (
        username VARCHAR(255) PRIMARY KEY,
        password_hash TEXT NOT NULL
      );
    `);
    this.db.run(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        from_username TEXT NOT NULL,
        to_username TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }

  insertUser(username: string, hashedPassword: string) {
    const query = this.db.prepare("INSERT INTO user_hashes (username, password_hash) VALUES (?, ?)");
    query.run(username, hashedPassword);
  }

  getHashedPassword(username: string) {
    const query = this.db.prepare("SELECT password_hash FROM user_hashes WHERE username = ? LIMIT 1");
    return (query.get(username) as userRow)?.password_hash;
  }

  insertMessage(fromUsername: string, toUsername: string, message: string) {
    const query = this.db.prepare("INSERT INTO messages (from_username, to_username, message) VALUES (?, ?, ?)");
    query.run(fromUsername, toUsername, message);
  }

  getMessages(fromUsername: string, toUsername: string) {
    const query = this.db.prepare("SELECT * FROM messages WHERE (from_username = ? AND to_username = ?) OR (from_username = ? AND to_username = ?) ORDER BY timestamp ASC");
    return query.all(fromUsername, toUsername, toUsername, fromUsername);
  }
};
