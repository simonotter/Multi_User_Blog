import hashlib
import hmac
import random
from string import letters

from google.appengine.ext import db

SECRET = 'khkhsakgioteb3s676*6753r5&^%$#'


class User(db.Model):
    """ Data object model for User.

    Attributes:
        name: A string representing the user's username.
        pw_hash: A string representing the user's hashed password.
        email: An (optional) string representing the user's email address.
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """ Gets a User by ID.

        Args:
            uid: An integer of the ID of the User.

        Returns:
            A User object with the ID of that user.
        """
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, username):
        """ Gets a User by Name.

        Args:
            username: A string of the user's username
        Returns:
            A User object with the username of that user.
        """
        user = User.all().filter('name =', username).get()
        return user

    @classmethod
    def register(cls, username, password, email=None):
        """ Makes a hashed password and creates a User object.

        Args:
            username: A string representing the user's username.
            password: A clear text string of the user's entered password.
            email: An (optional) string representing the user's email address.

        Returns:
            A User object.
        """
        password_hash = make_password_hash(username, password)
        return User(name=username,
                    pw_hash=password_hash,
                    email=email)

    @classmethod
    def login(cls, username, password):
        """ Checks if a user's username and password are valid.

        Args:
            username: A string representing the user's username.
            password: A clear text string of the user's entered password.

        Returns:
            The User object, if the username and password are valid.
        """
        user = cls.by_name(username)
        if user and valid_password_hash(username, password, user.pw_hash):
            return user


# --- functions for hashing password and cookie values ----
def make_secure_val(val):
    """ Hashes a value.

    Takes a value, creates a hmac hash using the SECRET constant.

    Args:
        val: A String of the value to be secured (e.g. a user id to be
             later stored in a cookie.)

    Returns:
        A String in the format val|secure_val ready to be stored in a cookie.
    """
    return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    """ Checks if a secure value has been tampered with.

    Takes a value and it's hashed value and checks if they are identical.

    Args:
        secure_val: A String in the format val|secure_val.

    Returns:
        A String of just the val if it has not been tampered with.
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
    """ Makes a random salt string for later use in hashing passwords.

    Args:
        length: (optional) integer for the length of the salt string.
                Default length is 5 characters.

    Returns:
        A string of random characters from String.letters
    """
    return ''.join(random.choice(letters) for x in xrange(length))


def make_password_hash(username, password, salt=None):
    """ Makes a secure hash from given clear text credentials

    Uses a combination of username, password and salt to create a sha256 hash

    Args:
        username: A string of the user's username.
        password: A clear text string of the user's entered password.
        salt: (optional) A string of the salt used in the orginal hashing of
              the password.

    Returns:
        A string in the format salt|password_hash
    """
    if not salt:
        salt = make_salt()  # make a new salt if one hasn't be provided
    password_hash = hashlib.sha256(username + password + salt).hexdigest()
    return '%s,%s' % (salt, password_hash)


def valid_password_hash(username, password, password_hash):
    """ Checks if a user's entered password is equal to it's hash

    Args:
        username: A string of the user's username.
        password: A clear text string of the user's entered password.
        password_hash: A string of the hash of user's password. (Which includes
                       a salt in the format salt|password_hash).

    Returns:
        A string of the hash of user's password, ff a valid password.
    """
    salt = password_hash.split(',')[0]
    return password_hash == make_password_hash(username, password, salt)
