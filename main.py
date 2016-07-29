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
import re
import webapp2

from user import *
from post import *
from helpers import render_str

from google.appengine.ext import db


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
        self.render('blog.html', posts=posts, user=self.user)


class PostPage(Handler):
    """ Renders a single Blog Post page with comments"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:  # if post is not found, raise a 404 error
            self.error(404)
            self.render('404error.html', user=self.user)
            return

        comments = Comment.all().filter("post =", post)
        self.render("permalink.html", post=post, comments=comments,
                    user=self.user)


class NewPostPage(Handler):
    """ Renders and Handles Submissions from the New Post form. """
    def get(self):
        """ Renders the new post form if the user is logged in. """
        if self.user:
            self.render('newpost.html', user=self.user)
        else:
            self.redirect('/login')

    def post(self):
        """ Handles submission of New Post form """
        if self.user:
            subject = self.request.get("subject")
            content = self.request.get("content")
            created_by = self.user
            post_id = self.request.get("post_id")

            if subject and content:
                if post_id:  # Post is being edited, so update existing post
                    post_key = db.Key.from_path('Post', int(post_id))
                    post = db.get(post_key)
                    # Check if user owns the post
                    if (post.created_by.key().id() ==
                            User.by_name(self.user.name).key().id()):
                        post.subject = subject
                        post.content = content
                    else:
                        msg = ("You cannot edit this post, "
                               "as it was not created by you.")
                        self.render('edit_post.html', msg=msg, user=self.user)

                else:  # No existing post_id, so create a new post
                    post = Post(subject=subject, content=content,
                                created_by=created_by)
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:  # subject or content are empty
                error = "Both subject and content are required"
                self.render('newpost.html', subject=subject,
                            content=content,
                            error=error, user=self.user)
        else:
            self.redirect('/login')


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
            self.render('confirmation.html', msg=msg, user=self.user)
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
                            post_id=post_id,
                            user=self.user)
            else:
                msg = ("You cannot edit this post, "
                       "as it was not created by you.")
                self.render('edit_post.html', msg=msg, user=self.user)
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
                # TODO: This will sometimes return more than one!
                liked_posts = post.likes.get()
                if liked_posts:  # there are some likes already on this post
                    # Check they haven't like it already
                    if user.name != liked_posts.user.name:
                        like = Like(post=post, user=user)
                        like.put()
                else:  # no likes on this post, so allow to add anyway
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
            self.render('comment_post.html', post_id=post_id, user=self.user)
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
                            error=msg,
                            user=self.user)
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
            self.render('confirmation.html', msg=msg, user=self.user)
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
                            post_id=comment.post.key().id(),
                            user=self.user)

            else:
                msg = ("You cannot edit this comment, "
                       "as it was not created by you.")
                self.render('confirmation.html', msg=msg, user=self.user)
        else:
            self.redirect('/login')


# ---- User Handlers ----
class SignUpHandler(Handler):
    """ Handles user sign-up. """
    def get(self):
        """ Renders signup form """
        self.render('signup.html', user=self.user)

    def post(self):
        """ Validates user signup form """
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.confirmed_password = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email,
                      user=self.user)

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
        """ make sure the user doesn't already exist,
            then add to datastore. """
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists."
            self.render('signup.html', error_username=msg, user=self.user)
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
        self.render('login.html', user=self.user)

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
            self.render('login.html', error=msg, user=self.user)


class WelcomeHandler(Handler):
    """ Handles welcoming the user. """
    def get(self):
        """ Renders the user welcome page. """
        if self.user:
            self.render('welcome.html', user=self.user)
        else:
            self.redirect('/signup')


class Logout(Handler):
    """ Handles user logout """
    def get(self):
        """ Logs out the current user. """
        self.logout()
        self.redirect('/blog')


app = webapp2.WSGIApplication([('/', BlogPage),
                               ('/blog/?', BlogPage),
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
                               ('/welcome', WelcomeHandler)], debug=True)
