### Migrations

Create new project template:

```bash
npm create hono@latest cloudflare-hono-lucia-auth
```

Users and sessions tables:

```sql
create table users
(
    id    TEXT not null primary key,
    email TEXT not null unique,
    hashed_password TEXT
);
create table sessions
(
    id         TEXT    not null primary key,
    expires_at INTEGER not null,
    user_id    TEXT    not null
);
```

Email verifications:

```sql
create table email_verification_codes
(
    id    INTEGER not null primary key,
    email TEXT,
    user_id TEXT unique,
    code TEXT,
    expires_at TEXT
);

alter table users add column email_verified boolean default false;
```

D1 commands:

```bash
npx wrangler d1 create lucia-email-and-password

npx wrangler d1 migrations create lucia-email-and-password init
npx wrangler d1 migrations create lucia-email-and-password email_verification
npx wrangler d1 migrations apply lucia-email-and-password
npx wrangler d1 migrations apply lucia-email-and-password --remote
```

### Hono sessions

```ts
c.header("Set-Cookie", sessionCookie.serialize(), {
  append: true,
});
```

Types:

```ts
type UserRow = {
  id: string;
  email: string;
  hashed_password: string;
  email_verified: boolean;
};

type EmailVerificationCode = {
  id: number;
  code: string;
  email: string;
  expires_at: string;
};

type Bindings = {
  DB: D1Database;
  DKIM_PRIVATE_KEY?: string;
};

interface DatabaseUserAttributes {
  email: string;
  email_verified: boolean;
}

declare module "lucia" {
  interface Register {
    Lucia: ReturnType<typeof initializeLucia>;
    DatabaseUserAttributes: DatabaseUserAttributes;
  }
}

const initializeLucia = (D1: D1Database) => {
  const adapter = new D1Adapter(D1, {
    user: "users",
    session: "sessions",
  });
  return new Lucia(adapter, {
    sessionCookie: {
      attributes: {
        secure: false,
      },
    },
    getUserAttributes: (attributes) => {
      return {
        email: attributes.email,
        emailVerified: Boolean(attributes.email_verified),
      };
    },
  });
};

const app = new Hono<{
  Bindings: Bindings;
  Variables: {
    user: User | null;
    session: Session | null;
  };
}>();
```

Send email or log:

```ts
const sendEmailOrLog = async (
  env: Bindings,
  recipient: string,
  subject: string,
  content: string,
) => {
  const body = {
    personalizations: [
      {
        to: [{ email: recipient }],
        dkim_domain: "habittra.com",
        dkim_selector: "mailchannels",
        dkim_private_key: env.DKIM_PRIVATE_KEY,
      },
    ],
    from: {
      email: "info@habittra.com",
      name: "Habittra",
    },
    subject: subject,
    content: [
      {
        type: "text/plain",
        value: content,
      },
    ],
  };

  if (env.DKIM_PRIVATE_KEY) {
    await fetch("https://api.mailchannels.net/tx/v1/send", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } else {
    console.log("Sending email");
    console.log(body);
  }
};
```
