# LeafRx 

This repo houses the backend codebase for the patient registration portal per the VT Capstone Prpject 


To get started 

- Create a python virtual environment
- Install the python requirements from requirements.txt `pip install -r requirements.txt`
- Download postgresql: on Mac, you can use homebrew
- For postgresql:
- # PostgreSQL Setup Guide for Mac

## Step 1: Install PostgreSQL via Homebrew

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install PostgreSQL
brew install postgresql

# Start PostgreSQL service
brew services start postgresql
```

## Step 2: Create Database and User

```bash
# Connect to PostgreSQL (using your macOS username as default superuser)
psql postgres

# Create a new user with password
CREATE USER your_username WITH PASSWORD 'your_password';

# Grant user privileges to create databases
ALTER USER your_username CREATEDB;

# Create your database
CREATE DATABASE your_database_name OWNER your_username;

# Grant all privileges on the database
GRANT ALL PRIVILEGES ON DATABASE your_database_name TO your_username;

# Exit PostgreSQL
\q
```

## Step 3: Test Your Connection

```bash
# Test connecting to your database
psql -U your_username -d your_database_name

# If successful, you'll see a prompt like: your_database_name=>
# Type \q to exit
```

## Step 4: Configure Your Flask Application

```python
# In your config.py or app configuration
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://your_username:your_password@localhost:5432/your_database_name"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
```

## Quick Verification Commands

```bash
# Check if PostgreSQL is running
brew services list | grep postgresql

# Check what's listening on PostgreSQL port
lsof -i :5432

# Connect directly to test
psql -U your_username -d your_database_name -h localhost -p 5432
```

## Default Settings
- **Port**: 5432 (PostgreSQL default)
- **Host**: localhost
- **Superuser**: Your macOS username (created automatically by Homebrew)
- **Authentication**: Local connections typically don't require password initially

## Troubleshooting
- If you get "connection refused": run `brew services start postgresql`
- If you get "authentication failed": make sure you're using the correct username and password
- If you are having issues with the DB having the most up to date schema, try adding the following code to the app.py file and execute it under the main

with app.app_context():
    db.drop_all()
    db.create_all()
- If you get "database does not exist": create the database first using Step 2
