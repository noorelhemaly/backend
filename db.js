const sqlite = require('sqlite3')
const db = new sqlite.Database('auction.db')

const createUSERtable = `CREATE TABLE IF NOT EXISTS USER (
  ID INTEGER PRIMARY KEY AUTOINCREMENT,
  NAME TEXT NOT NULL,
  IDNUMBER INTEGER UNIQUE NOT NULL,
  EMAIL TEXT UNIQUE NOT NULL,
  PASSWORD TEXT NOT NULL,
  ISADMIN INTEGER NOT NULL DEFAULT 0
  )`

const createLISTINGtable = `CREATE TABLE IF NOT EXISTS LISTING (
  ID INTEGER PRIMARY KEY AUTOINCREMENT,
  CATEGORY TEXT NOT NULL,
  IMAGE_URL TEXT,
  NAME TEXT NOT NULL,
  BRAND TEXT NOT NULL,
  STYLE TEXT NOT NULL,
  SIZE TEXT NOT NULL,
  COLOR TEXT,
  HARDWARE TEXT,
  MATERIAL TEXT,
  STARTING_BID REAL NOT NULL,
  CURRENT_BID REAL NOT NULL,
  STATUS TEXT DEFAULT 'ACTIVE',
  DURATION INTEGER NOT NULL,
  END_AT DATETIME NOT NULL
  )`
  
const createBIDDINGtable = `CREATE TABLE IF NOT EXISTS BIDDING (
  ID INTEGER PRIMARY KEY AUTOINCREMENT,
  USER_ID INT,
  LISTING_ID INT,
  BID_AMOUNT REAL NOT NULL,
  CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(USER_ID) REFERENCES USER(ID),
  FOREIGN KEY(LISTING_ID) REFERENCES LISTING(ID)
  )`;
  
module.exports = {db,createUSERtable,createLISTINGtable,createBIDDINGtable}