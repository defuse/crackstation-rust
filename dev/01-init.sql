-- Schema initialization for crackstation-rust development environment.
-- Creates the phpcount database with CrackStation-specific table names.
--
-- Passwords here are dev-only placeholders. Production uses different credentials.

-- ============================================================================
-- phpcount - Page hit counter (CrackStation uses cshits/csnodupes table names)
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `phpcount` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

CREATE USER IF NOT EXISTS 'phpcount'@'%' IDENTIFIED BY 'dev_phpcount_pass';
GRANT ALL PRIVILEGES ON `phpcount`.* TO 'phpcount'@'%';

USE `phpcount`;

CREATE TABLE IF NOT EXISTS `cshits` (
  `pageid` varchar(100) NOT NULL,
  `isunique` tinyint(1) NOT NULL,
  `hitcount` int(10) unsigned NOT NULL,
  KEY `pageid` (`pageid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

CREATE TABLE IF NOT EXISTS `csnodupes` (
  `ids_hash` char(64) NOT NULL,
  `time` bigint(20) unsigned NOT NULL,
  PRIMARY KEY (`ids_hash`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ============================================================================

FLUSH PRIVILEGES;
