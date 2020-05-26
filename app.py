# coding: utf8

from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, Markup, Response, json
import redis
import time
from datetime import datetime, timedelta
import os
import base64
import codecs
from base64 import b64encode, b64decode, urlsafe_b64decode, urlsafe_b64encode

app = Flask(__name__)

# key for cookie safety. Shal be overridden using ENV var SECRET_KEY
app.secret_key = os.getenv("SECRET_KEY", "lasfuoi3ro8w7gfow3bwiubdwoeg7p23r8g23rg")

# Description of info keys
# TODO: to be continued.
serverinfo_meta = {
}


@app.route("/", methods=['GET', 'POST'])
def login():
    """
    Start page
    """
    if request.method == 'POST':
        # TODO: test connection, handle failures
        host = request.form["host"]
        # host = host.encode('utf-8')
        # host = base64.urlsafe_b64encode(host)
        # host_decode = base64.urlsafe_b64decode(host.encode("utf8"))
        # host = hash(host)
        # host = base64.urlsafe_b64encode(bytes(host))
        port = int(request.form["port"])
        db = int(request.form["db"])
        url = url_for("server_db", host=host, port=port, db=db)
        return redirect(url)
    else:
        s = time.time()
        return render_template('login.html',
            duration=time.time()-s)


@app.route("/<host>:<int:port>/<int:db>/")
def server_db(host, port, db):
    """
    List all databases and show info on server
    """
    # host = base64.urlsafe_b64decode(host.encode("utf8"))
    # host = hash(host)
    s = time.time()
    r = redis.StrictRedis(host=host, port=port, db=0)
    info = r.info("all")
    dbsize = r.dbsize()
    return render_template('server.html',
        host=host,
        port=port,
        db=db,
        info=info,
        dbsize=dbsize,
        serverinfo_meta=serverinfo_meta,
        duration=time.time()-s)


@app.route("/<host>:<int:port>/<int:db>/keys/", methods=['GET', 'POST'])
def keys(host, port, db):
    """
    List keys for one database
    """
    s = time.time()
    # host = base64.urlsafe_b64decode(host.encode("utf8"))
    r = redis.StrictRedis(host=host, port=port, db=db)
    if request.method == "POST":
        action = request.form["action"]
        app.logger.debug(action)
        if action == "delkey":
            if request.form["key"] is not None:
                result = r.delete(request.form["key"])
                if result == 1:
                    flash("Key %s has been deleted." % request.form["key"], category="info")
                else:
                    flash("Key %s could not be deleted." % request.form["key"], category="error")
        return redirect(request.url)
    else:
        offset = int(request.args.get("offset", "0"))
        perpage = int(request.args.get("perpage", "10"))
        pattern = request.args.get('pattern', '*')
        dbsize = r.dbsize()
        keys = sorted(r.keys(pattern))
        # type_keys = type(keys)
        limited_keys = keys[offset:(perpage+offset)]
        types = {}
        for key in limited_keys:
            types[key] = r.type(key)
        return render_template('keys.html',
            host=host,
            port=port,
            db=db,
            dbsize=dbsize,
            keys=limited_keys,
            types=types,
            offset=offset,
            perpage=perpage,
            pattern=pattern,
            num_keys=len(keys),
            duration=time.time()-s)


@app.route("/<host>:<int:port>/<int:db>/keys/<key>/")
def key(host, port, db, key):
    """
    Show a specific key.
    key is expected to be URL-safe base64 encoded
    """
    key = base64.urlsafe_b64decode(key.encode("utf8"))
    key = key.decode('utf-8')

    s = time.time()
    r = redis.StrictRedis(host=host, port=port, db=db)
    # r = r.decode('utf-8')

    dump = r.dump(key)
    if dump is None:
        abort(404)
    #if t is None:
    #    abort(404)
    size = len(dump)
    del dump
    # t = key.decode('utf-8')
    # t = r.type
    t = r.type(key)
    # t = base64.urlsafe_b64encode(t)
    t = str(t.decode('utf-8'))
    ttl = r.pttl(key)
    # val = val = r.get(key).decode('utf-8', 'replace')
    string = "b'string'"
    if t == "string":
        val = r.get(key).decode('utf-8', 'replace')
    elif t == "list":
        val = r.lrange(key, 0, -1)
    elif t == "hash":
        val = r.hgetall(key)
    elif t == "set":
        val = r.smembers(key)
    elif t == "zset":
        val = r.zrange(key, 0, -1, withscores=True)
    else:
        val = "Gagal"
    return render_template('key.html',
        host=host,
        port=port,
        db=db,
        key=key,
        value=val,
        type=t,
        size=size,
        ttl=ttl / 1000.0,
        now=datetime.utcnow(),
        expiration=datetime.utcnow() + timedelta(seconds=ttl / 1000.0),
        duration=time.time()-s)


@app.route("/<host>:<int:port>/<int:db>/pubsub/")
def pubsub(host, port, db):
    """
    List PubSub channels
    """
    s = time.time()
    return render_template('pubsub.html',
        host=host,
        port=port,
        db=db,
        duration=time.time()-s)


def pubsub_event_stream(host, port, db, pattern):
    r = redis.StrictRedis(host=host, port=port, db=db)
    p = r.pubsub()
    p.psubscribe(pattern)
    for message in p.listen():
        if message["type"] != "psubscribe" and message["data"] != "1":
            yield 'data: %s\n\n' % json.dumps(message)


@app.route("/<host>:<int:port>/<int:db>/pubsub/api/")
def pubsub_ajax(host, port, db):
    return Response(pubsub_event_stream(host, port, db, pattern="*"),
           mimetype="text/event-stream")


@app.template_filter('urlsafe_base64')
def urlsafe_base64_encode(s):
    if type(s) == 'Markup':
        s = s.unescape(s)
    # s = s.encode(bytes(encoding='utf-8'))
    # s = codecs.encode(s, 'utf-8').decode('utf-8')
    # s = s.encode(str('utf-8'))
    # s = s.encode(str('utf-8'))
    # print(s)
    # s = str(s, 'utf-8')
    # s = s.decode('utf-8')
    s = base64.urlsafe_b64encode(s)
    s = s.decode("utf-8")
    # print(s)
    return Markup(s)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5001, threaded=True)


# from flask import Flask
# import os
# import flask_login
#
# app = Flask(__name__)
#
# # key for cookie safety. Shal be overridden using ENV var SECRET_KEY
# app.secret_key = os.getenv("SECRET_KEY", "lasfuoi3ro8w7gfow3bwiubdwoeg7p23r8g23rg")
#
# login_manager = flask_login.LoginManager()
#
# login_manager.init_app(app)
#
# users = {'foo@bar.tld': {'password': 'secret'}}
#
# class User(flask_login.UserMixin):
#     pass
#
#
# @login_manager.user_loader
# def user_loader(email):
#     if email not in users:
#         return
#
#     user = User()
#     user.id = email
#     return user
#
#
# @login_manager.request_loader
# def request_loader(request):
#     email = request.form.get('email')
#     if email not in users:
#         return
#
#     user = User()
#     user.id = email
#
#     # DO NOT ever store passwords in plaintext and always compare password
#     # hashes using constant-time comparison!
#     user.is_authenticated = request.form['password'] == users[email]['password']
#
#     return user
#
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if flask.request.method == 'GET':
#         return '''
#                <form action='login' method='POST'>
#                 <input type='text' name='email' id='email' placeholder='email'/>
#                 <input type='password' name='password' id='password' placeholder='password'/>
#                 <input type='submit' name='submit'/>
#                </form>
#                '''
#
#     email = flask.request.form['email']
#     if flask.request.form['password'] == users[email]['password']:
#         user = User()
#         user.id = email
#         flask_login.login_user(user)
#         return flask.redirect(flask.url_for('protected'))
#
#     return 'Bad login'
#
#
# @app.route('/protected')
# @flask_login.login_required
# def protected():
#     return 'Logged in as: ' + flask_login.current_user.id
#
# @app.route('/logout')
# def logout():
#     flask_login.logout_user()
#     return 'Logged out'
#
# @login_manager.unauthorized_handler
# def unauthorized_handler():
#     return 'Unauthorized'