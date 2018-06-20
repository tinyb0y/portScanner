from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
import os
from config import basedir,SQLALCHEMY_DATABASE_URI
from datetime import datetime
db = SQLAlchemy()
engine = create_engine(SQLALCHEMY_DATABASE_URI, echo=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

# Set your classes here.

class Scan(Base):
    __tablename__ = 'scan'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(120))
    service = db.Column(db.String(255))
    port = db.Column(db.Integer)
    updated = db.Column(
                    db.DateTime, nullable=False)


# Create tables.
sqlfilename = basedir + '/database.db'
# print(filename)
if not os.path.exists(sqlfilename):
    Base.metadata.create_all(bind=engine)
