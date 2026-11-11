-- ==============================================================================
-- SQL Script: Dedicated MySQL Accounts for Antigravity AI MCP Integration
-- Execute this script as MySQL root/administrator on your remote VPS.
-- Replace `<YOUR_DEV_DATABASE>`, `<READER_PASSWORD>`, and `<WRITER_PASSWORD>`
-- with your actual values before running.
-- ==============================================================================

-- 1. Create dedicated read-only user (Strictly SELECT and SHOW VIEW only)
CREATE USER IF NOT EXISTS 'ai_agent_reader'@'127.0.0.1' IDENTIFIED BY '<READER_PASSWORD>';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'ai_agent_reader'@'127.0.0.1';
GRANT SELECT, SHOW VIEW ON `<YOUR_DEV_DATABASE>`.* TO 'ai_agent_reader'@'127.0.0.1';

-- 2. Create dedicated write user (Strictly SELECT, INSERT, UPDATE only)
-- Explicitly NO DELETE, DROP, ALTER, TRUNCATE, CREATE, GRANT, EXECUTE.
CREATE USER IF NOT EXISTS 'ai_agent_writer'@'127.0.0.1' IDENTIFIED BY '<WRITER_PASSWORD>';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'ai_agent_writer'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `<YOUR_DEV_DATABASE>`.* TO 'ai_agent_writer'@'127.0.0.1';

-- 3. Flush privileges to apply changes immediately
FLUSH PRIVILEGES;

-- 4. Verification queries
SHOW GRANTS FOR 'ai_agent_reader'@'127.0.0.1';
SHOW GRANTS FOR 'ai_agent_writer'@'127.0.0.1';
