/**
 * Database Initialization Script
 * Creates tables and populates with sample data
 */

const Database = require('better-sqlite3');
const md5 = require('md5');

const db = new Database('./database.sqlite');

console.log('Initializing database...');

// Create tables
db.exec(`
    -- Users table
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE,
        role TEXT DEFAULT 'user',
        address TEXT,
        phone TEXT,
        ssn TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Products table
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL,
        stock INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Accounts table (for banking demo)
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        account_number TEXT UNIQUE,
        balance REAL DEFAULT 0,
        account_type TEXT DEFAULT 'checking',
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    -- Orders table
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        product_id INTEGER,
        quantity INTEGER,
        total REAL,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
    );

    -- Sessions table
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT,
        expires_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    -- Logs table (mostly empty - A09 vulnerability)
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        user_id INTEGER,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

// Clear existing data
db.exec(`
    DELETE FROM users;
    DELETE FROM products;
    DELETE FROM accounts;
    DELETE FROM orders;
`);

// Insert sample users (A04: MD5 password hashing)
const users = [
    { username: 'admin', password: 'admin123', email: 'admin@vulnerable.local', role: 'admin', address: '123 Admin St', phone: '555-0100', ssn: '123-45-6789' },
    { username: 'john', password: 'password123', email: 'john@vulnerable.local', role: 'user', address: '456 User Ave', phone: '555-0101', ssn: '234-56-7890' },
    { username: 'jane', password: 'letmein', email: 'jane@vulnerable.local', role: 'user', address: '789 Test Blvd', phone: '555-0102', ssn: '345-67-8901' },
    { username: 'bob', password: 'qwerty', email: 'bob@vulnerable.local', role: 'manager', address: '321 Manager Ln', phone: '555-0103', ssn: '456-78-9012' },
    { username: 'alice', password: '123456', email: 'alice@vulnerable.local', role: 'user', address: '654 Alice Way', phone: '555-0104', ssn: '567-89-0123' },
];

const insertUser = db.prepare(`
    INSERT INTO users (username, password, email, role, address, phone, ssn)
    VALUES (?, ?, ?, ?, ?, ?, ?)
`);

users.forEach(user => {
    insertUser.run(
        user.username,
        md5(user.password),  // A04: Weak hashing
        user.email,
        user.role,
        user.address,
        user.phone,
        user.ssn
    );
});

// Insert sample products
const products = [
    { name: 'Laptop Pro X', description: 'High-performance laptop for professionals', price: 1299.99, stock: 50 },
    { name: 'Wireless Mouse', description: 'Ergonomic wireless mouse with USB receiver', price: 29.99, stock: 200 },
    { name: 'USB-C Hub', description: '7-in-1 USB-C hub with HDMI and SD card reader', price: 49.99, stock: 150 },
    { name: 'Mechanical Keyboard', description: 'RGB mechanical keyboard with Cherry MX switches', price: 149.99, stock: 75 },
    { name: '4K Monitor', description: '27-inch 4K IPS monitor with HDR support', price: 399.99, stock: 30 },
    { name: 'Webcam HD', description: '1080p webcam with built-in microphone', price: 79.99, stock: 100 },
    { name: 'Noise Cancelling Headphones', description: 'Premium wireless headphones with ANC', price: 299.99, stock: 45 },
    { name: 'Portable SSD 1TB', description: 'Fast external SSD with USB 3.2', price: 109.99, stock: 80 },
];

const insertProduct = db.prepare(`
    INSERT INTO products (name, description, price, stock)
    VALUES (?, ?, ?, ?)
`);

products.forEach(product => {
    insertProduct.run(product.name, product.description, product.price, product.stock);
});

// Insert sample accounts
const accounts = [
    { user_id: 1, account_number: 'ACC001', balance: 50000.00, account_type: 'checking' },
    { user_id: 2, account_number: 'ACC002', balance: 2500.00, account_type: 'checking' },
    { user_id: 2, account_number: 'ACC003', balance: 10000.00, account_type: 'savings' },
    { user_id: 3, account_number: 'ACC004', balance: 750.00, account_type: 'checking' },
    { user_id: 4, account_number: 'ACC005', balance: 15000.00, account_type: 'checking' },
    { user_id: 5, account_number: 'ACC006', balance: 3200.00, account_type: 'savings' },
];

const insertAccount = db.prepare(`
    INSERT INTO accounts (user_id, account_number, balance, account_type)
    VALUES (?, ?, ?, ?)
`);

accounts.forEach(account => {
    insertAccount.run(account.user_id, account.account_number, account.balance, account.account_type);
});

console.log('Database initialized successfully!');
console.log(`
Created:
- ${users.length} users (admin password: admin123)
- ${products.length} products
- ${accounts.length} accounts

Default credentials:
- admin:admin123 (admin role)
- john:password123 (user role)
- jane:letmein (user role)
- bob:qwerty (manager role)
- alice:123456 (user role)
`);

db.close();
