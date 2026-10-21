from app import db

# This model stores candidates for each electoral division

class Candidate(db.Model):
    __tablename__ = 'candidates'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    party = db.Column(db.String(200), nullable=False)
    division = db.Column(db.String(100), nullable=False)
    ballot_position = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<Candidate {self.name}>'