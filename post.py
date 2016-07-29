from google.appengine.ext import db
from user import *
from helpers import render_str


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
    post = db.ReferenceProperty(Post, required=True,
                                collection_name='comments')
    user = db.ReferenceProperty(User, required=True,
                                collection_name='comments')
    comment = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        """ Renders the comment into HTML. """
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comment.html", post=self)
