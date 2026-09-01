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

-- PRIMARY KEY (pageid, isunique) is upstream PHPCount's, and it is load-bearing:
-- create_counts_if_not_present does a SELECT then an INSERT with no transaction, so
-- two concurrent first-hits on the same page both see "absent" and both insert.
-- Without the key the table then carries duplicate rows for one (pageid, isunique),
-- count_hit's UPDATE increments all of them, and get_hit_counts reads only one back,
-- so the displayed count silently diverges from the number of hits recorded. The key
-- makes the losing INSERT fail instead, which is the behaviour the code was written
-- against. csnodupes kept its PRIMARY KEY; this one had been weakened to a plain KEY.
CREATE TABLE IF NOT EXISTS `cshits` (
  `pageid` varchar(100) NOT NULL,
  `isunique` tinyint(1) NOT NULL,
  `hitcount` int(10) unsigned NOT NULL,
  PRIMARY KEY (`pageid`, `isunique`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- KEY (`time`) is what keeps the expiry sweep off a full table scan. `cleanup` runs
-- `DELETE FROM csnodupes WHERE time < ?` on every counted page view, under a MyISAM
-- table-level write lock, so without it the whole site serialises behind that scan.
-- Measured on production, 23 MB file and ~200k live rows: 20 ms without the index,
-- 1 ms with it.
CREATE TABLE IF NOT EXISTS `csnodupes` (
  `ids_hash` char(64) NOT NULL,
  `time` bigint(20) unsigned NOT NULL,
  PRIMARY KEY (`ids_hash`),
  KEY `time` (`time`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ============================================================================

FLUSH PRIVILEGES;
