#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, render_template
import logging
from logging import Formatter, FileHandler
import models as models
import os
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#

app = Flask(__name__)
app.config.from_object('config')

engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], echo=False)
Session = sessionmaker(bind=engine)
Session.configure(bind=engine)

session = Session()

# Automatically tear down SQLAlchemy.

#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#


@app.route('/')
@app.route('/index')
def home():
    scans = session.query(models.Scan).all()
    return render_template('pages/placeholder.home.html', scans=scans)


@app.route('/about')
def about():
    return render_template('pages/placeholder.about.html')

# Error handlers.

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setFormatter(
        Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('errors')

#----------------------------------------------------------------------------#
# Launch.
#----------------------------------------------------------------------------#


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
