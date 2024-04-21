import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { generateId } from "lucia";
import type { User, Session } from "lucia";
import { verifyRequestOrigin, Scrypt } from "lucia";
import { getCookie } from "hono/cookie";
import { isWithinExpirationDate } from "oslo";

import type { FC } from "hono/jsx";
import { Lucia } from "lucia";
import { D1Adapter } from "@lucia-auth/adapter-sqlite";

import { TimeSpan, createDate } from "oslo";
import { generateRandomString, alphabet } from "oslo/crypto";

async function generateEmailVerificationCode(
  db: D1Database,
  userId: string,
  email: string,
) {
  await db
    .prepare("delete from email_verification_codes where user_id = ?")
    .bind(userId)
    .run();

  const code = generateRandomString(8, alphabet("0-9"));
  await db
    .prepare(
      "insert into email_verification_codes (user_id, email, code, expires_at) values (?,?,?,?)",
    )
    .bind(userId, email, code, createDate(new TimeSpan(15, "m")).toString())
    .run();
  return code;
}

function initializeLucia(D1: D1Database) {
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
}

interface DatabaseUserAttributes {
  email: string;
  email_verified: number;
}

declare module "lucia" {
  interface Register {
    Auth: ReturnType<typeof initializeLucia>;
    DatabaseUserAttributes: DatabaseUserAttributes;
  }
}

type UserRow = {
  id: string;
  email: string;
  hashed_password: string;
  email_verified: number;
};

type EmailVerificationCode = {
  id: number;
  code: string;
  email: string;
  expires_at: string;
};

const Layout: FC = (props) => {
  return (
    <html>
      <body>{props.children}</body>
    </html>
  );
};

type Bindings = {
  DB: D1Database;
  DKIM_PRIVATE_KEY?: string;
};

const app = new Hono<{
  Bindings: Bindings;
  Variables: {
    user: User | null;
    session: Session | null;
  };
}>();

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

app.use("*", async (c, next) => {
  if (c.req.method === "GET") {
    return next();
  }
  const originHeader = c.req.header("Origin");
  const hostHeader = c.req.header("Host");
  if (
    !originHeader ||
    !hostHeader ||
    !verifyRequestOrigin(originHeader, [hostHeader])
  ) {
    return c.body(null, 403);
  }
  return next();
});

app.use("*", async (c, next) => {
  const lucia = initializeLucia(c.env.DB);
  const sessionId = getCookie(c, lucia.sessionCookieName) ?? null;
  if (!sessionId) {
    c.set("user", null);
    c.set("session", null);
    return next();
  }
  const { session, user } = await lucia.validateSession(sessionId);
  if (session && session.fresh) {
    // use `header()` instead of `setCookie()` to avoid TS errors
    c.header("Set-Cookie", lucia.createSessionCookie(session.id).serialize(), {
      append: true,
    });
  }
  if (!session) {
    c.header("Set-Cookie", lucia.createBlankSessionCookie().serialize(), {
      append: true,
    });
  }
  c.set("user", user);
  c.set("session", session);
  return next();
});

app.get("/", (c) => {
  const user = c.get("user");
  if (user) {
    return c.html(
      <Layout>
        {user.emailVerified ? (
          <div>Current user: {JSON.stringify(user)}</div>
        ) : (
          <form method="POST" action="/email-verification">
            <input name="code" />
            <button>verify</button>
          </form>
        )}

        <form method="POST" action="/logout">
          <button>logout</button>
        </form>
      </Layout>,
    );
  } else {
    return c.html(
      <Layout>
        <a href="/signup">signup</a>
        <br />
        <a href="/login">login</a>
      </Layout>,
    );
  }
});

app.get("/signup", (c) => {
  return c.html(
    <Layout>
      <form method="POST">
        <input name="email" autocomplete="off" />
        <input name="password" />
        <button>signup</button>
      </form>
    </Layout>,
  );
});

app.get("/login", (c) => {
  return c.html(
    <Layout>
      <form method="POST">
        <input name="email" autocomplete="off" />
        <input name="password" />
        <button>login</button>
      </form>
    </Layout>,
  );
});

app.post(
  "/signup",
  zValidator(
    "form",
    z.object({
      email: z.string().email(),
      password: z.string().min(1),
    }),
  ),
  async (c) => {
    const { email, password } = c.req.valid("form");
    const lucia = initializeLucia(c.env.DB);

    const hashedPassword = await new Scrypt().hash(password);
    const userId = generateId(15);

    try {
      const insertedUser = await c.env.DB.prepare(
        "insert into users (id, email, hashed_password, email_verified) values (?,?,?,?) returning *",
      )
        .bind(userId, email, hashedPassword, false)
        .first();
      console.log("New user");
      console.log(insertedUser);

      const verificationCode = await generateEmailVerificationCode(
        c.env.DB,
        userId,
        email,
      );
      console.log(verificationCode);

      await sendEmailOrLog(
        c.env,
        email,
        "Welcome",
        "Your verification code is " + verificationCode,
      );

      const session = await lucia.createSession(userId, {});
      const sessionCookie = lucia.createSessionCookie(session.id);
      c.header("Set-Cookie", sessionCookie.serialize(), {
        append: true,
      });
      return c.redirect("/");
    } catch (error) {
      console.error(error);
      return c.body("Something went wrong", 400);
    }
  },
);

app.post(
  "/login",
  zValidator(
    "form",
    z.object({
      email: z.string().email(),
      password: z.string().min(1),
    }),
  ),
  async (c) => {
    const { email, password } = c.req.valid("form");
    const lucia = initializeLucia(c.env.DB);

    const user = await c.env.DB.prepare("select * from users where email = ?")
      .bind(email)
      .first<UserRow>();

    if (!user) {
      return c.body("Invalid email or password", 400);
    }
    const validPassword = await new Scrypt().verify(
      user.hashed_password,
      password,
    );
    if (!validPassword) {
      return c.body("Invalid email or password", 400);
    }

    const session = await lucia.createSession(user.id, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    c.header("Set-Cookie", sessionCookie.serialize(), {
      append: true,
    });
    return c.redirect("/");
  },
);

app.post("/logout", async (c) => {
  const lucia = initializeLucia(c.env.DB);
  const session = c.get("session");
  if (session) {
    await lucia.invalidateSession(session.id);
  }
  const sessionCookie = lucia.createBlankSessionCookie();
  c.header("Set-Cookie", sessionCookie.serialize(), {
    append: true,
  });
  return c.redirect("/");
});

async function verifyVerificationCode(
  db: D1Database,
  user: User,
  code: string,
) {
  const databaseCode = await db
    .prepare(
      "delete from email_verification_codes where user_id = ? and code = ? and email = ? returning *",
    )
    .bind(user.id, code, user.email)
    .first<EmailVerificationCode>();

  if (!databaseCode) {
    return false;
  }

  if (!isWithinExpirationDate(new Date(databaseCode.expires_at))) {
    return false;
  }

  return true;
}

app.post(
  "/email-verification",
  zValidator(
    "form",
    z.object({
      code: z.string().min(1),
    }),
  ),
  async (c) => {
    const user = c.get("user");
    const { code } = c.req.valid("form");
    if (!user) {
      return c.body(null, 400);
    }
    const validCode = await verifyVerificationCode(c.env.DB, user, code);
    if (!validCode) {
      return c.body(null, 400);
    }

    const lucia = initializeLucia(c.env.DB);
    await lucia.invalidateUserSessions(user.id);
    await c.env.DB.prepare("update users set email_verified = ? where id = ?")
      .bind(true, user.id)
      .run();

    const session = await lucia.createSession(user.id, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    c.header("Set-Cookie", sessionCookie.serialize(), {
      append: true,
    });
    return c.redirect("/");
  },
);

export default app;
