-- Migration number: 0002 	 2024-04-21T14:56:58.228Z
create table email_verification_codes
(
    id    INTEGER not null primary key,
    email TEXT,
    user_id TEXT unique,
    code TEXT,
    expires_at TEXT
);

alter table users add column email_verified boolean default false;
