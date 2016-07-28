#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import hashlib
import hmac
import os
import random
import re
from string import letters

import jinja2
import webapp2

from google.appengine.ext import db

# establish jinja template directory
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)  # autoescape by default

SECRET = 'khkhsakgioteb3s676*6753r5&^%$#'

def render_str(template, **params):
    """ Renders a Jinja HTML template.

    Takes a template and list of parameters and renders them into HTML.

    Args:
        template: A string of the filename of the template in the template
                  directory.
        **params: Arbitrary keyword arguments

    Returns:
        A string of the rendered HTML containing the parameters provided.
    """
    t = jinja_env.get_template(template)
    return t.render(params)


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
        salt = make_salt() # make a new salt if one hasn't be provided
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


class Post(db.Model):
    """ Data object model for Blog Post.

    Attributes:
        subject: A string of the subject of the blog post.
        content: A string of the content of the blog post.
        created: The datetime when the blog post was created.
        created_by: The user who created the blog post.
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.ReferenceProperty(User, required=True,
                                      collection_name='posts')

    @classmethod
    def get_top_10(cls):
        """ Retrieves top 10 latest blog posts """
        return db.GqlQuery("SELECT * FROM Post "
                            "ORDER BY created DESC limit 10")

    def render(self):
        """ Renders the blog post into HTML. """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post=self)

    def delete(self, post_key):
        """ Deletes a post from the datastore """
        db.delete(post_key)
        # TODO: Should really delete any corresponding likes
        #       and comments too (else they're be orphaned)


class Like(db.Model):
    """ Data object model for Liking a Blog Post.

    Attributes:
        post: The Blog Post being liked.
        user: The User that is liking the Blog Post.
    """
    post = db.ReferenceProperty(Post, required=True, collection_name='likes')
    user = db.ReferenceProperty(User, required=True, collection_name='likes')


class Comment(db.Model):
    """ Data object model for Commenting on a Blog Post.

    Attributes:
        post: The Blog Post being commented on.
        user: The User making the comment on the Blog Post.
        comment: A string of the comment being made on the Blog Post.
        created: The datetime when the comment was created.
    """
    post = db.ReferenceProperty(Post, required=True, collection_name='comments')
    user = db.ReferenceProperty(User, required=True, collection_name='comments')
    comment = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        """ Renders the comment into HTML. """
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comment.html", post=self)


class Handler(webapp2.RequestHandler):
    """ Base class to handle web requests. """
    def write(self, *a, **kw):
        """ Helper function to write to the web response. """
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        """ Helper function to render a given HTML template and write it
            to the web Response. """
        self.write(render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """ Sets a name=value pair as a user cookie. The value is hashed.

        Args:
            name: A string of the name of the cookie.
            val: A string representing the value to be stored.

        Returns:
            A string in the format name=hashed_value.
        """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """ Reads a value and it's hash from cookie, compares if they have
            been tampered with.

        Args:
            name: A string of the name of the cookie.

        Returns:
            A string of the clear text value of the cookie, if the value is
            equivalent to it's hash.
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """ Stores a secure cookie of the user's ID

        Args:
            user: A string of the user's username

        Returns: none
        """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """ Reset's the user_id cookie """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """ Called on every web Request action, reads the user_id from
            the cookie and retreives the user's User object from the datastore.
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class BlogPage(Handler):
    """ Renders the Main Blog Home page. """
    def get(self):
        posts = Post.get_top_10()
        self.render('blog.html', posts=posts)


class PostPage(Handler):
    """ Renders a single Blog Post page with comments"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post: # if post is not found, raise a 404 error
            self.error(404)
            return

        comments = Comment.all().filter("post =", post)
        self.render("permalink.html", post=post, comments=comments)


class NewPostPage(Handler):
    """ Renders and Handles Submissions from the New Post form. """
    def get(self):
        """ Renders the new post form if the user is logged in. """
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')

    def post(self):
        """ Handles submission of New Post form """
        subject = self.request.get("subject")
        content = self.request.get("content")
        created_by = self.user
        post_id = self.request.get("post_id")

        if subject and content:
            if post_id:  # Post is being edited, so must update existing post
                post_key = db.Key.from_path('Post', int(post_id))
                post = db.get(post_key)
                post.subject = subject
                post.content = content
            else: # No existing post_id, so create a new post
                post = Post(subject=subject, content=content,
                            created_by=created_by)
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else: # subject or content are empty
            error = "Both subject and content are required"
            self.render('newpost.html', subject=subject,
                        content=content,
                        error=error)


class DeletePost(Handler):
    """ Handles deletion of a post """
    def post(self):
        """ Removes a post from the datastore if user owns that post """
        if self.user:
            post_id = self.request.get('post_id')
            post_key = db.Key.from_path('Post', int(post_id))
            post = db.get(post_key)

            # Check if user owns the post
            if (post.created_by.key().id() ==
                User.by_name(self.user.name).key().id()):

                post.delete(post_key)
                msg = "Your post has been successfully deleted."

            else:
                msg = ("You cannot delete this post, "
                       "as it was not created by you.")
            self.render('confirmation.html', msg=msg)
        else:
            self.redirect('/login')


class EditPost(Handler):
    """ Handles the editing of a post """
    def post(self):
        """ Checks if the user owns that post and redirects to the New
            Post form with the existing post details filled out. """
        if self.user:
            post_id = self.request.get('post_id')
            post_key = db.Key.from_path('Post', int(post_id))
            post = db.get(post_key)

            # Check if user owns the post
            if (post.created_by.key().id() ==
                User.by_name(self.user.name).key().id()):
                self.render('newpost.html',
                            subject=post.subject,
                            content=post.content,
                            post_id=post_id)
            else:
                msg = ("You cannot edit this post, "
                       "as it was not created by you.")
                self.render('edit_post.html', msg=msg)
        else:
            self.redirect('/login')


class LikePost(Handler):
    """ Handles liking of a post. """
    def get(self):
        """ Checks if user doesn't own that post and creates a Like """
        if self.user:
            post_id = self.request.get('post_id')
            post_key = db.Key.from_path('Post', int(post_id))
            post = db.get(post_key)

            user = User.by_name(self.user.name)
            # Check if user owns the post
            if post.created_by.key().id() != user.key().id():
                # Check if user has already liked the post (can only like once)
                liked_posts = post.likes.get() # TODO: This will sometimes return more than one!
                if liked_post: #
                    if user.name != liked_posts.user.name: # Check they haven't like it already
                        like = Like(post=post, user=user)
                        like.put()
                self.redirect('/blog')
            else:
                self.redirect('/blog')

        else:
            self.redirect('/login')


class CommentPost(Handler):
    """ Handles commenting of a post. """
    def get(self):
        """ Renders comment form if user is logged in. """
        if self.user:  # if logged in user
            post_id = self.request.get('post_id')
            self.render('comment_post.html', post_id=post_id)
        else:
            self.redirect('/login')

    def post(self):
        """ Creates a new comment and updates an existing comment. """
        if self.user:  # if logged in user
            post_id = self.request.get('post_id')
            comment_str = self.request.get('comment')
            comment_id = self.request.get('comment_id')

            if post_id and comment_str:  # if these exist
                post_key = db.Key.from_path('Post', int(post_id))
                post = db.get(post_key)
                user = User.by_name(self.user.name)

                if comment_id:  # Comment is being edited, so must update
                    comment_key = db.Key.from_path('Comment', int(comment_id))
                    comment = db.get(comment_key)
                    comment.comment = comment_str
                else:  # else create a new one
                    comment = Comment(post=post, user=user,
                                      comment=comment_str)

                comment.put()
                self.redirect('/blog/' + post_id)
            else:  # comment is blank
                msg = "Comment cannot be empty"
                self.render('comment_post.html',
                            post_id=post_id,
                            error=msg)
        else:
            self.redirect('/login')


class DeleteComment(Handler):
    """ Handles deletion of Comments """
    def post(self):
        """ Deletes a comment if user owns that comment. """
        if self.user:  # if logged in user
            comment_id = self.request.get('comment_id')
            comment_key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(comment_key)
            # Check if user owns the post
            if (comment.user.key().id() ==
                User.by_name(self.user.name).key().id()):

                db.delete(comment_key)
                msg = "Your comment has been successfully deleted."

            else:
                msg = ("You cannot delete this comment, "
                       "as it was not created by you.")
            self.render('confirmation.html', msg=msg)
        else:
            self.redirect('/login')


class EditComment(Handler):
    """ Handles Editing of Comments """
    def post(self):
        """ Checks if user owns that comment and redirects to comment form. """
        if self.user:  # if logged in user
            comment_id = self.request.get('comment_id')
            comment_key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(comment_key)
            # Check if user owns the post
            if (comment.user.key().id() ==
                User.by_name(self.user.name).key().id()):

                self.render('comment_post.html',
                            comment=comment.comment,
                            comment_id=comment_id,
                            post_id=comment.post.key().id())

            else:
                msg = ("You cannot edit this comment, "
                       "as it was not created by you.")
                self.render('confirmation.html', msg=msg)
        else:
            self.redirect('/login')


# ---- User Handlers ----
class SignUpHandler(Handler):
    """ Handles user sign-up. """
    def get(self):
        """ Renders signup form """
        self.render('signup.html')

    def post(self):
        """ Validates user signup form """
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.confirmed_password = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not self.isValidUserName(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not self.isValidPassword(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.confirmed_password:
            params['error_verify'] = "The passwords do not match."
            have_error = True

        if self.email:
            if not self.isValidEmail(self.email):
                params['error_email'] = "That's not a valid email address."
                have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self):
        """ make sure the user doesn't already exist, then add to datastore. """
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists."
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

    def isValidUserName(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    def isValidPassword(self, password):
        PASSWORD_RE = re.compile(r"^.{3,20}$")
        return PASSWORD_RE.match(password)

    def isValidEmail(self, email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return EMAIL_RE.match(email)


class Login(Handler):
    """ Handles user login """
    def get(self):
        """ Renders the login form. """
        self.render('login.html')

    def post(self):
        """ Validates user password and logs the user in. """
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class WelcomeHandler(Handler):
    """ Handles welcoming the user. """
    def get(self):
        """ Renders the user welcome page. """
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Logout(Handler):
    """ Handles user logout """
    def get(self):
        """ Logs out the current user. """
        self.logout()
        self.redirect('/blog')

app = webapp2.WSGIApplication([('/blog/?', BlogPage),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPostPage),
                               ('/blog/deletepost', DeletePost),
                               ('/blog/editpost', EditPost),
                               ('/blog/likepost', LikePost),
                               ('/blog/commentpost', CommentPost),
                               ('/blog/deletecomment', DeleteComment),
                               ('/blog/editcomment', EditComment),
                               ('/signup', SignUpHandler),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', WelcomeHandler),], debug=True)
