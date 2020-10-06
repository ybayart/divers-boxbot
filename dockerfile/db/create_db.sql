CREATE DATABASE box;
\c box;
CREATE TABLE mac_filter (addr macaddr unique, name varchar(50) unique, active boolean);
