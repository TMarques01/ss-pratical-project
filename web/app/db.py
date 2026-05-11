from . import utils

def get_user_by_username(cur, username):
    query, params = utils.prepare_query("SELECT id, username, password, is_disabled FROM users WHERE username=%s", (username,))
    cur.execute(query, params)
    return cur.fetchone()


def disable_user_by_id(cur, user_id):
    query, params = utils.prepare_query("UPDATE users SET is_disabled = TRUE WHERE id = %s", (user_id,))
    cur.execute(query, params)

def enable_user_by_id(cur, user_id):
    query, params = utils.prepare_query("UPDATE users SET is_disabled = FALSE WHERE id = %s", (user_id,))
    cur.execute(query, params)

def get_all_users(cur):
    query, params = utils.prepare_query("SELECT id, username, is_disabled FROM users ORDER BY id", ())
    cur.execute(query, params)
    return cur.fetchall()
