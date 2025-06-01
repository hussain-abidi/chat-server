import { randomUUID } from "crypto";

export class UserSession {
  username: string;

  token: string;
  valid: boolean;

  constructor(username: string) {
    this.username = username;

    this.token = randomUUID();
    this.valid = true;

    setTimeout(() => { this.valid = false }, 60 * 60 * 10); // 1 hour
  }
}
