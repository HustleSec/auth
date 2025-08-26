import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

export async function openDB() {
  return open({
    filename: './database.sqlite',
    driver: sqlite3.Database
  });
}

export async function init()
{
	const db = await openDB()
	let icon_url = "https://www.meme-arsenal.com/memes/0854907ebde1bf28f572b7e99dbf5601.jpg"
	await db.exec(`
		CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		avatarurl TEXT NOT NULL DEFAULT '${icon_url}',
		refreshToken TEXT,
		createdAt TEXT DEFAULT CURRENT_TIMESTAMP
	);`);
	return db
}
