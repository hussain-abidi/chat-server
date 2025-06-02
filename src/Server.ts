import { type ServerWebSocket } from "bun";
import { Database } from "bun:sqlite";
import { randomUUID } from "crypto";

const CORS_HEADERS = {
  headers: {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'OPTIONS, POST',
    'Access-Control-Allow-Headers': 'Content-Type',
  },
};

interface WsData {
  id: number,
  token: string;
};

type SocketType = ServerWebSocket<WsData>;

export class Server {
  counter = 0;

  port: number;

  sockets = new Map<number, SocketType>();

  tokens = new Map<string, string>();

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
        if (req.method === "OPTIONS") {
          return new Response(null, CORS_HEADERS);
        }
        const url = new URL(req.url);

        switch (url.pathname) {
          case "/register": {
            if (req.method !== "POST") { break; }
            const reqJson = await req.json();

            const username = reqJson.username;
            const password = reqJson.password;

            if (!username || !password) {
              return new Response("Empty credentials are not allowed", { status: 400, ...CORS_HEADERS });
            }

            const query = this.db.prepare("SELECT 1 FROM user_hashes WHERE username = ? LIMIT 1");
            const row = query.get(username);

            if (row) {
              return new Response("Username already exists", { status: 400, ...CORS_HEADERS });
            }

            const hashedPassword = await Bun.password.hash(password);

            const insertQuery = this.db.prepare("INSERT INTO user_hashes(username, password_hash) VALUES(?, ?)");

            insertQuery.run(username, hashedPassword);

            return new Response("Registered successfully", CORS_HEADERS);
          }

          case "/login": {
            if (req.method !== "POST") { break; }
            const reqJson = await req.json();

            const username = reqJson.username;
            const password = reqJson.password;

            if (this.tokens.has(username)) {
              return new Response("Already logged in", { status: 409, ...CORS_HEADERS });
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

              const token = randomUUID();
              this.tokens.set(username, token);

              return Response.json({ token }, CORS_HEADERS);
            }

            return new Response("Invalid credentials", { status: 401, ...CORS_HEADERS });
          }

          case "/ws": {
            const token = url.searchParams.get("token");
            if (!token || !Array.from(this.tokens.values()).includes(token)) {
              return new Response("Unauthorized", { status: 401, ...CORS_HEADERS });
            }

            const data: WsData = { id: this.counter++, token };

            if (server.upgrade(req, { data })) {
              return;
            }

            return new Response("Upgrade failed", { status: 500, ...CORS_HEADERS });
          }

          default: {
            return new Response("Not found", { status: 404, ...CORS_HEADERS });
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

    console.log(`Message received from client ${id}: ${message.trim()}`);
  }

  socketClose(ws: SocketType) {
    const id = ws.data.id;
    const token = ws.data.token;

    this.sockets.delete(id);

    console.log(`Client ${id} disconnected.`);
  }
};
