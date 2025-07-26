-- users table for students
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(8) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    college VARCHAR(255),
    roll_no VARCHAR(50) UNIQUE,
    email VARCHAR(255) UNIQUE NOT NULL,
    address TEXT,
    contact VARCHAR(20),
    role VARCHAR(50) NOT NULL, -- 'student', 'admin'
    year VARCHAR(50),
    branch VARCHAR(100),
    department VARCHAR(100),
    password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS admin (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

-- mentors table
CREATE TABLE IF NOT EXISTS mentors (
    user_id VARCHAR(8) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    college VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    expertise TEXT,
    skills TEXT,
    password VARCHAR(255) NOT NULL
);

-- events table
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY, -- SERIAL automatically increments (like AUTOINCREMENT in SQLite)
    title VARCHAR(255) NOT NULL,
    description TEXT,
    date DATE, -- Or TIMESTAMP if you need time
    short_description TEXT,
    image_path VARCHAR(255)
);

-- event_stages table
CREATE TABLE IF NOT EXISTS event_stages (
    id SERIAL PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, -- Foreign key, delete stages if event is deleted
    stage_title VARCHAR(255) NOT NULL,
    deadline DATE NOT NULL -- Or TIMESTAMP if you need time
);

-- event_registrations table
CREATE TABLE IF NOT EXISTS event_registrations (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(8) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, event_id) -- A user can only register for an event once
);

-- submissions table
CREATE TABLE IF NOT EXISTS submissions (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(8) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    stage_id INTEGER NOT NULL REFERENCES event_stages(id) ON DELETE CASCADE,
    submission_text TEXT,
    submission_file VARCHAR(255),
    submitted_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, event_id, stage_id) -- A user can only submit once per stage per event
);

-- brainstorm_rooms table
CREATE TABLE IF NOT EXISTS brainstorm_rooms (
    room_id VARCHAR(8) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    created_by VARCHAR(8) NOT NULL, -- Could be user_id from users or mentors
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- brainstorm_chats table
CREATE TABLE IF NOT EXISTS brainstorm_chats (
    id SERIAL PRIMARY KEY,
    room_id VARCHAR(8) NOT NULL REFERENCES brainstorm_rooms(room_id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- event_results table
CREATE TABLE IF NOT EXISTS event_results (
    id SERIAL PRIMARY KEY,
    event_title VARCHAR(255) NOT NULL,
    position VARCHAR(50) NOT NULL, -- e.g., '1st', '2nd', '3rd'
    winner_name VARCHAR(255) NOT NULL,
    winner_email VARCHAR(255) NOT NULL,
    announced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add an index for faster lookups on user_id in brainstorm_chats
CREATE INDEX IF NOT EXISTS idx_brainstorm_chats_room_id ON brainstorm_chats (room_id);

-- Add an index for faster lookups on event_id in event_stages
CREATE INDEX IF NOT EXISTS idx_event_stages_event_id ON event_stages (event_id);

-- Add indexes for common foreign key lookups
CREATE INDEX IF NOT EXISTS idx_event_registrations_user_event ON event_registrations (user_id, event_id);
CREATE INDEX IF NOT EXISTS idx_submissions_user_event_stage ON submissions (user_id, event_id, stage_id);

-- Consider adding indexes on frequently queried columns (e.g., email, roll_no if often used in WHERE clauses)
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_mentors_email ON mentors (email);
CREATE INDEX IF NOT EXISTS idx_users_roll_no ON users (roll_no);