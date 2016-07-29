import os
import jinja2


# establish jinja template directory
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)  # autoescape by default


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
