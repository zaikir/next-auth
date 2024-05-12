/**
 * <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", padding: 16}}>
 *  <p>An official <a href="https://www.postgresql.org/">PostgreSQL</a> adapter for Auth.js / NextAuth.js.</p>
 *  <a href="https://www.postgresql.org/">
 *   <img style={{display: "block"}} src="/img/adapters/pg.svg" width="48" />
 *  </a>
 * </div>
 *
 * ## Installation
 *
 * ```bash npm2yarn
 * npm install next-auth @auth/pg-adapter pg
 * ```
 *
 * @module @auth/pg-adapter
 */

import type {
  Adapter,
  AdapterUser,
  VerificationToken,
  AdapterSession,
} from "next-auth/adapters"
import type { Pool } from "pg"

export function mapExpiresAt(account: any): any {
  const expires_at: number = parseInt(account.expires_at)
  return {
    ...account,
    expires_at,
  }
}


const buildUser = (row: any): AdapterUser => {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    emailVerified: row.email_verified_at,
    image: null
  }
}

export default function PostgresAdapter(client: Pool): Adapter {
  return {
    async createVerificationToken(
      verificationToken: VerificationToken
    ): Promise<VerificationToken> {
      const { identifier, expires, token } = verificationToken
      const sql = `
        INSERT INTO verification_token ( identifier, expires, token ) 
        VALUES ($1, $2, $3)
        `
      await client.query(sql, [identifier, expires, token])
      return verificationToken
    },
    async useVerificationToken({
      identifier,
      token,
    }: {
      identifier: string
      token: string
    }): Promise<VerificationToken> {
      const sql = `delete from verification_token
      where identifier = $1 and token = $2
      RETURNING identifier, expires, token `
      const result = await client.query(sql, [identifier, token])
      return result.rowCount !== 0 ? result.rows[0] : null
    },

    async createUser(user: Omit<AdapterUser, "id">) {
      const { name, email, emailVerified } = user
      const sql = `
        INSERT INTO user (name, email, email_verified_at) 
        VALUES ($1, $2, $3) 
        RETURNING id, name, email, email_verified_at`
      const result = await client.query(sql, [
        name,
        email,
        emailVerified,
      ])

      return buildUser(result.rows[0])
    },
    async getUser(id) {
      const sql = `select * from user where id = $1`
      try {
        const result = await client.query(sql, [id])
        return result.rowCount === 0 ? null : buildUser(result.rows[0])
      } catch (e) {
        return null
      }
    },
    async getUserByEmail(email) {
      const sql = `select * from user where email = $1`
      const result = await client.query(sql, [email])
      return result.rowCount === 0 ? null : buildUser(result.rows[0])
    },
    async getUserByAccount({
      providerAccountId,
      provider,
    }): Promise<AdapterUser | null> {
      const sql = `
          select u.* from user u join account a on u.id = a.user_id
          where 
          a.provider = $1 
          and 
          a.provider_account_id = $2`

      const result = await client.query(sql, [provider, providerAccountId])
      return result.rowCount === 0 ? null : buildUser(result.rows[0])
    },
    async updateUser(user: Partial<AdapterUser>): Promise<AdapterUser> {
      const fetchSql = `select * from user where id = $1`
      const query1 = await client.query(fetchSql, [user.id])
      const oldUser = query1.rows[0]

      const newUser = {
        ...oldUser,
        ...user,
        ...user.emailVerified ? {email_verified_at: user.emailVerified}: {}
      }

      const { id, name, email, email_verified_at } = newUser
      const updateSql = `
        UPDATE user set
        name = $2, email = $3, email_verified_at = $4
        where id = $1
        RETURNING name, id, email, email_verified_at
      `
      const query2 = await client.query(updateSql, [
        id,
        name,
        email,
        email_verified_at,
      ])
      return buildUser(query2.rows[0])
    },
    async linkAccount(account) {
      const sql = `
      insert into account
      (
        user_id, 
        provider, 
        type, 
        provider_account_id, 
        access_token,
        expires_at,
        refresh_token,
        id_token,
        scope,
        session_state,
        token_type
      )
      values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      returning
        id,
        user_id, 
        provider, 
        type, 
        provider_account_id, 
        access_token,
        expires_at,
        refresh_token,
        id_token,
        scope,
        session_state,
        token_type
      `

      const params = [
        account.userId,
        account.provider,
        account.type,
        account.providerAccountId,
        account.access_token,
        account.expires_at,
        account.refresh_token,
        account.id_token,
        account.scope,
        account.session_state,
        account.token_type,
      ]

      const result = await client.query(sql, params)
      const row = result.rows[0]

      return mapExpiresAt({
        id: row.id,
        userId: row.user_id, 
        provider: row.provider, 
        type: row.type, 
        providerAccountId: row.provider_account_id, 
        access_token: row.access_token,
        expires_at: row.expires_at,
        refresh_token: row.refresh_token,
        id_token: row.id_token,
        scope: row.scope,
        session_state: row.session_state,
        token_type: row.token_type
      })
    },
    async createSession({ sessionToken, userId, expires }) {
      if (userId === undefined) {
        throw Error(`userId is undef in createSession`)
      }
      const sql = `insert into session (user_id, expires, session_token)
      values ($1, $2, $3)
      RETURNING id, session_token, user_id, expires`

      const result = await client.query(sql, [userId, expires, sessionToken])
      const row = result.rows[0]
      return {
        id: row.id,
        userId: row.user_id,
        sessionToken: row.session_token,
        expires: row.expires
      }
    },

    async getSessionAndUser(sessionToken: string | undefined): Promise<{
      session: AdapterSession
      user: AdapterUser
    } | null> {
      if (sessionToken === undefined) {
        return null
      }
      const result1 = await client.query(
        `select * from session where session_token = $1`,
        [sessionToken]
      )
      if (result1.rowCount === 0) {
        return null
      }
      let session: any = result1.rows[0]

      const result2 = await client.query("select * from user where id = $1", [
        session.user_id,
      ])
      if (result2.rowCount === 0) {
        return null
      }
      const user = result2.rows[0]
      return {
        session: {
          id: session.id,
          userId: session.user_id,
          sessionToken: session.session_token,
          expires: session.expires
        } as any,
        user: buildUser(user),
      }
    },
    async updateSession(
      session: Partial<AdapterSession> & Pick<AdapterSession, "sessionToken">
    ): Promise<AdapterSession | null | undefined> {
      const { sessionToken } = session
      const result1 = await client.query(
        `select * from session where "session_token" = $1`,
        [sessionToken]
      )
      if (result1.rowCount === 0) {
        return null
      }
      const originalSession: AdapterSession = result1.rows[0]

      const newSession: any = {
        ...originalSession,
        ...session.sessionToken !== undefined && {session_token: session.sessionToken},
        ...session.expires !== undefined && {expires: session.expires}
      }
      const sql = `
        UPDATE session set
        expires = $2
        where "session_token" = $1
        `
      const result = await client.query(sql, [
        newSession.session_token,
        newSession.expires,
      ])
      return result.rows[0]
    },
    async deleteSession(sessionToken) {
      const sql = `delete from session where "session_token" = $1`
      await client.query(sql, [sessionToken])
    },
    async unlinkAccount(partialAccount) {
      const { provider, providerAccountId } = partialAccount
      const sql = `delete from account where "provider_account_id" = $1 and provider = $2`
      await client.query(sql, [providerAccountId, provider])
    },
    async deleteUser(userId: string) {
      await client.query(`delete from user where id = $1`, [userId])
      await client.query(`delete from session where "user_id" = $1`, [userId])
      await client.query(`delete from account where "user_id" = $1`, [userId])
    },
  }
}
