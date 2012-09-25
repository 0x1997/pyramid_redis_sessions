import base64
import time
from Crypto import Random
from pyramid.compat import text_
from pyramid.interfaces import ISession
from zope.interface import implementer

from .util import serialize, deserialize, persist, refresh

@implementer(ISession)
class RedisSession(object):
    """ Implements the Pyramid ISession and IDict interfaces and is returned by
    the RedisSessionFactory.

    Methods that modify the ``dict`` (get, set, update, etc.) are decorated
    with ``@persist`` to update the persisted copy in Redis and reset the
    timeout.

    Methods that are read-only (items, keys, values, etc.) are decorated
    with ``@refresh`` to reset the session's expire time in Redis.

    Session methods make use of the dict methods that already communicate with
    Redis, so they are not decorated.

    Parameters:

    ``redis``
    A Redis connection object.

    ``session_id``
    A unique string associated with the session. Used as a prefix for keys
    and hashes associated with the session.

    ``timeout``
    Keys will be set to expire in ``timeout`` seconds on each read/write
    access. If keys are not accessed for the duration of a ``timeout``,
    Redis will remove them.

    ``delete_cookie``
    A function that takes no arguments and returns nothing, but should have the
    side effect of deleting the session cookie from the ``response`` object.

    ``encode``
    A function to serialize pickleable Python objects. Default:
    ``cPickle.dumps``.

    ``decode``
    The dual of ``encode``, to convert serialized strings back to Python
    objects. Default: ``cPickle.loads``.
    """

    def __init__(self, redis, session_id, timeout, delete_cookie):
        self.session_id = session_id
        self.redis = redis
        self.managed_dict = self.from_redis()

        self.default_timeout = timeout
        self.timeout = 0 if 'on' in self.managed_dict else timeout

        self.delete_cookie = delete_cookie
        self.created = time.time()

    def to_redis(self):
        """ Encode this session's ``managed_dict`` for storage in Redis.
        Primarily used by the ``@persist`` decorator to save the current session
        state to Redis.
        """
        return serialize(self.managed_dict)

    def from_redis(self):
        """ Get this session's serialized ``dict`` from Redis."""
        persisted = self.redis.get(self.session_id)
        return deserialize(persisted)

    # dict modifying methods decorated with @persist
    @persist
    def __delitem__(self, key):
        del self.managed_dict[key]

    @persist
    def __setitem__(self, key, value):
        self.managed_dict[key] = value

    @persist
    def setdefault(self, key, default=None):
        return self.managed_dict.setdefault(key, default)

    @persist
    def clear(self):
        return self.managed_dict.clear()

    @persist
    def pop(self, key, default=None):
        return self.managed_dict.pop(key, default)

    @persist
    def update(self, other):
        return self.managed_dict.update(other)

    @persist
    def popitem(self):
        return self.managed_dict.popitem()

    # dict read-only methods decorated with @refresh
    @refresh
    def __getitem__(self, key):
        return self.managed_dict[key]

    @refresh
    def __contains__(self, key):
        return key in self.managed_dict

    @refresh
    def keys(self):
        return self.managed_dict.keys()

    @refresh
    def items(self):
        return self.managed_dict.items()

    @refresh
    def get(self, key, default=None):
        return self.managed_dict.get(key, default)

    @refresh
    def __iter__(self):
        return self.managed_dict.__iter__()

    @refresh
    def has_key(self, key):
        return key in self.managed_dict

    @refresh
    def values(self):
        return self.managed_dict.values()

    @refresh
    def itervalues(self):
        return self.managed_dict.itervalues()

    @refresh
    def iteritems(self):
        return self.managed_dict.iteritems()

    @refresh
    def iterkeys(self):
        return self.managed_dict.iterkeys()

    @persist
    def changed(self):
        """ Persists the working dict immediately with ``@persist``."""
        pass

    @persist
    def set_timeout(self):
        self.timeout = self.default_timeout
        if 'on' in self.managed_dict:
            del self.managed_dict['on']

    @persist
    def dont_expire(self):
        self.timeout = 0
        self.managed_dict['on'] = True

    # session methods persist or refresh using above dict methods
    @property
    def new(self):
        return getattr(self, '_v_new', False)

    def invalidate(self):
        """ Delete all keys unique to this session and expire cookie."""
        self.clear()
        self.delete_cookie()

    def new_csrf_token(self):
        token = text_(base64.b64encode(Random.new().read(20)))
        self['csrf'] = token
        return token

    def get_csrf_token(self):
        token = self.get('csrf', None)
        if token is None:
            token = self.new_csrf_token()
        else:
            token = unicode(token)
        return token

    def flash(self, msg, queue='', allow_duplicate=True):
        storage = self.setdefault('_f_' + queue, [])
        if allow_duplicate or (msg not in storage):
            storage.append(msg)
            self.changed() # notify redis of change to ``storage`` mutable

    def peek_flash(self, queue=''):
        storage = self.get('_f_' + queue, [])
        return storage

    def pop_flash(self, queue=''):
        storage = self.pop('_f_' + queue, [])
        return storage
