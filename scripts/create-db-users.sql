-- ==============================================================================
-- SQL Script: Dedicated MySQL Accounts for AI Agent MCP Integration
-- Execute this script as MySQL root/administrator.
-- Replace `<YOUR_DEV_DATABASE>`, `<READER_PASSWORD>`, and `<WRITER_PASSWORD>`.
-- ==============================================================================

-- 1. Create dedicated read-only user (Strictly SELECT and SHOW VIEW)
-- Note: Use @'%' for remote/cloud MySQL (DigitalOcean, RDS) or @'127.0.0.1' for SSH tunnel.
CREATE USER IF NOT EXISTS 'ai_agent_reader'@'%' IDENTIFIED BY '<READER_PASSWORD>';
GRANT SELECT, SHOW VIEW ON `<YOUR_DEV_DATABASE>`.* TO 'ai_agent_reader'@'%';

-- 2. Create dedicated writer user (Restricted DML only)
-- Explicitly NO DROP, ALTER, TRUNCATE, CREATE, GRANT, EXECUTE or admin privileges.
CREATE USER IF NOT EXISTS 'ai_agent_writer'@'%' IDENTIFIED BY '<WRITER_PASSWORD>';
GRANT SELECT, INSERT, UPDATE, DELETE ON `<YOUR_DEV_DATABASE>`.* TO 'ai_agent_writer'@'%';

-- 3. Flush privileges to apply changes immediately
FLUSH PRIVILEGES;

-- 4. Verification queries
SHOW GRANTS FOR 'ai_agent_reader'@'%';
SHOW GRANTS FOR 'ai_agent_writer'@'%';
