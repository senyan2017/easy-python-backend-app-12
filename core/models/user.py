from mongoengine import Document, StringField, DateTimeField, signals
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(Document):
    username = StringField(required=True, unique=True)
    password = StringField(required=True)
    email = StringField(required=True, unique=True)
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super(User, self).save(*args, **kwargs)


    def to_dict(self):
        # Public representation safe to return to clients (never includes password)
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


    @classmethod
    def find_one(cls, **kwargs):
        if 'password' in kwargs:
            del kwargs['password']  # Do not use password in these queries
        return cls.objects(**kwargs).first()
    

def generate_password(sender, document, **kwargs):  
    if document.password and not document.password.startswith('pbkdf2:sha256'):  
        document.password = generate_password_hash(document.password, method='pbkdf2:sha256')

    
def set_update_time(sender, document, **kwargs):  
    document.updated_at = datetime.utcnow()

signals.pre_save.connect(generate_password, sender=User)  # pre_save signal to hash password
signals.pre_save.connect(set_update_time, sender=User)  # pre_save signal to update timestamp