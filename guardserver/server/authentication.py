from . import app
import ldap
from flask import request, Response, make_response
from functools import wraps
import re
import json

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    valid = re.match("^[\w.]+$", username) is not None
    if not valid:
        return False
    user_dn = app.config["LDAP_DN"] % username
    connect = ldap.initialize(app.config["LDAP_SERVER"])
    try:
        connect.bind_s(user_dn, password)
        if "CURRENT_USER" not in app.config:
            result = connect.search_st(app.config["LDAP_OU"], ldap.SCOPE_SUBTREE, "cn=" + username)
            given_name = result[0][1]["givenName"][0]
            last_name = result[0][1]["sn"][0]
            name = given_name + " " + last_name
            app.config["CURRENT_USER"] = name
        return True
    except ldap.LDAPError, e:
        connect.unbind_s()
        return False


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if app.config["AUTHENTICATION_REQUIRED"]:
            if not auth or not check_auth(auth.username, auth.password):
                return authenticate()
        return f(*args, **kwargs)

    return decorated

@app.route("/current_user", methods=["GET"])
@requires_auth
def current_user():
    user = ""
    if "CURRENT_USER" in app.config:
        user = app.config["CURRENT_USER"]
    result = dict(name=user)
    response = make_response(json.dumps(result))
    response.headers["Content-Type"] = "application/json"
    return response
