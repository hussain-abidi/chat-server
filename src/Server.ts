import { type ServerWebSocket } from "bun";
import { UserSession } from "./User";
import { Database } from "bun:sqlite";

interface WsData {
  id: number,
  username: string;
  token: string;
};

type SocketType = ServerWebSocket<WsData>;

export class Server {
  counter = 0;

  port: number;

  sockets = new Map<number, SocketType>();

  sessions = new Map<string, UserSession>();

  db: Database;

  constructor(port: number) {
    this.port = port;

    this.db = new Database("users.sqlite");
    this.db.run(`
      CREATE TABLE IF NOT EXISTS user_hashes (
        username VARCHAR(255) PRIMARY KEY,
        password_hash TEXT NOT NULL
      );
    `);
  }

  run() {
    Bun.serve({
      port: this.port,
      fetch: async (req, server) => {
        const url = new URL(req.url);

        switch (url.pathname) {
          case "/register": {
            if (req.method !== "POST") { break; }
            const reqJson = await req.json();

            const username = reqJson.username;
            const password = reqJson.password;

            const query = this.db.prepare("SELECT 1 FROM user_hashes WHERE username = ? LIMIT 1");
            const row = query.get(username);

            if (row) {
              return new Response("Username already exists", { status: 400 });
            }

            const hashedPassword = await Bun.password.hash(password);

            const insertQuery = this.db.prepare("INSERT INTO user_hashes(username, password_hash) VALUES(?, ?)");

            insertQuery.run(username, hashedPassword);

            return new Response("Registered successfully");
          }

          case "/login": {
            if (req.method !== "POST") { break; }
            const reqJson = await req.json();

            const username = reqJson.username;
            const password = reqJson.password;

            // unnecessary looping?
            for (const session of this.sessions.values()) {
              if (session.username === username && session.valid) {
                return new Response("Already logged in", { status: 409 });
              }
            }

            const query = this.db.prepare("SELECT password_hash FROM user_hashes WHERE username = ? LIMIT 1") as {
              get: (params: any) => { password_hash: string } | undefined;
            };

            const row = query.get(username);

            // labeled if statement
            login: if (row) {
              const hashedPassword = row.password_hash;

              if (!hashedPassword || !await Bun.password.verify(password, hashedPassword)) {
                break login;
              }

              const session = new UserSession(username);
              const token = session.token;

              this.sessions.set(token, session);

              console.log(`User ${username} logged in.`);
              return Response.json({ token });
            }

            return new Response("Invalid credentials", { status: 401 });
          }

          case "/ws": {
            const token = url.searchParams.get("token");
            const username = token ? this.sessions.get(token)?.username : null;

            if (!token || !username) {
              return new Response("Unauthorized", { status: 401 });
            }

            const data: WsData = { id: this.counter++, username, token };

            if (server.upgrade(req, { data })) {
              return;
            }

            return new Response("Upgrade failed", { status: 500 });
          }

          default: {
            return new Response("Not found", { status: 404 });
          }
        }
      },
      websocket: {
        open: (ws: SocketType) => this.socketOpen(ws),
        message: (ws: SocketType, message: string) => this.socketMessage(ws, message),
        close: (ws: SocketType) => this.socketClose(ws)
      },
    });

    console.log(`Server listening on port ${this.port}.`);
  }

  socketOpen(ws: SocketType) {
    const id = ws.data.id;
    this.sockets.set(id, ws);

    console.log(`Client ${id} connected from ${ws.remoteAddress}.`);
  }

  socketMessage(ws: SocketType, message: string) {
    const id = ws.data.id;
    const token = ws.data.token;

    const session = this.sessions.get(token)!;
    if (!session.valid) {
      console.log(`Client ${id} timeout.`);
      ws.close(3008);

      return;
    }

    console.log(`Message received from client ${id}: ${message.trim()}`);
  }

  socketClose(ws: SocketType) {
    const id = ws.data.id;
    const token = ws.data.token;

    this.sockets.delete(id);

    const session = this.sessions.get(token)!;
    this.sessions.delete(token);

    console.log(`User ${session.username} logged out.`);

    console.log(`Client ${id} disconnected.`);
  }
};
