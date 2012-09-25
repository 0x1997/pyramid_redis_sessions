import base64
import hmac
import msgpack
from hashlib import sha1
from Crypto import Random
from pyramid.compat import text_, bytes_, native_
from pyramid.util import strings_differ


_packer = msgpack.Packer()
_unpacker = msgpack.Unpacker()

def serialize(obj):
    return _packer.pack(obj)


def deserialize(str):
    _unpacker.feed(str)
    return _unpacker.unpack()


def sign_session_id(session_id, secret):
    sig = hmac.new(bytes_(secret), session_id, sha1).digest()
    return base64.b32encode(sig) + session_id


def unsign_session_id(cookie, secret):
    cookie = bytes_(cookie)
    input_sig, session_id = (cookie[:32], cookie[32:])
    sig = hmac.new(bytes_(secret), session_id, sha1).digest()

    # Avoid timing attacks (see
    # http://seb.dbzteam.org/crypto/python-oauth-timing-hmac.pdf)
    if strings_differ(base64.b32encode(sig), input_sig):
        raise ValueError('Invalid signature')
    return session_id


_empty_session = serialize({})

def new_session_id(redis, timeout):
    """ Returns a unique session id after inserting it successfully in Redis."""
    while 1:
        session_id = base64.b32encode(Random.new().read(20))
        val = redis.setnx(session_id, _empty_session)
        if val[0] is True:
            if timeout:
                redis.expire(session_id, timeout)
            return session_id


def parse_settings(settings):
    """ Convenience function to collect settings prefixed by 'redis.sessions'.
    Coerces 'true' and 'false' (case insensitive) to bools.
    """
    options = {}
    for k in settings:
        if k.startswith('redis.sessions.'):
            param = k.split('.')[-1]
            value = settings[k]
            # coerce bools
            if hasattr(value, 'lower') and value.lower() in ['true', 'false']:
                value = value.lower() == 'true'
            options[param] = value

    # coerce ints
    for i in ('port', 'db'):
        if i in options:
            options[i] = int(options[i])

    return options

def refresh(wrapped):
    """Decorator to reset the expire time for this session's key in Redis.
    """
    def wrapped_refresh(session, *arg, **kw):
        result = wrapped(session, *arg, **kw)
        if session.timeout:
            session.redis.expire(session.session_id, session.timeout)
        return result
    return wrapped_refresh

def persist(wrapped):
    """ Decorator to persist the working session copy in Redis and reset the
    expire time.
    """
    def wrapped_persist(session, *arg, **kw):
        result = wrapped(session, *arg, **kw)
        if session.timeout:
            session.redis.setex(session.session_id, session.timeout, session.to_redis())
        else:
            session.redis.set(session.session_id, session.to_redis())
        return result
    return wrapped_persist
