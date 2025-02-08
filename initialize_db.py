import sqlite3

def initialize_db():
    # Connect to the SQLite database (it will be created if it doesn't exist)
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    #  additional table creation commands here if needed
    # For example:
    # c.execute('''
    #     CREATE TABLE IF NOT EXISTS tasks (
    #         id INTEGER PRIMARY KEY AUTOINCREMENT,
    #         title TEXT NOT NULL,
    #         description TEXT,
    #         estimated_time INTEGER
    #     )
    # ''')

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    initialize_db()



