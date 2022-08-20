import click

from chongming import app, db
from chongming.models import MetaNVD


@app.cli.command()
@click.option('--drop', is_flag=True, help='Create after drop.')
def initdb(drop):
    """Initialize the database."""
    db.create_all()
    click.echo('Initialized database.')