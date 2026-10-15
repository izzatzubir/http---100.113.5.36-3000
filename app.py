import os
import re
import hmac
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Ephemeral session key in RAM
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////data/sources.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# In-memory storage for the active cipher (Wiped on lock or reboot)
ACTIVE_CIPHER = None

def get_cipher():
    global ACTIVE_CIPHER
    return ACTIVE_CIPHER

def encrypt_val(val: str) -> str:
    cipher = get_cipher()
    if not cipher or not val:
        return ""
    return cipher.encrypt(val.encode('utf-8')).decode('utf-8')

def decrypt_val(val: str) -> str:
    cipher = get_cipher()
    if not cipher or not val:
        return "[LOCKED]"
    try:
        return cipher.decrypt(val.encode('utf-8')).decode('utf-8')
    except Exception:
        return "[DECRYPTION FAILED]"

# --- DATABASE MODELS ---

class ContactRelation(db.Model):
    __tablename__ = 'contact_relation'
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey('contact.id', ondelete='CASCADE'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('contact.id', ondelete='CASCADE'), nullable=False)
    relationship_note = db.Column(db.String(255), nullable=False)

    @property
    def note(self):
        return decrypt_val(self.relationship_note)

class Contact(db.Model):
    __tablename__ = 'contact'
    id = db.Column(db.Integer, primary_key=True)
    _name = db.Column("name", db.String(255), nullable=False)
    _phone = db.Column("phone", db.String(255), nullable=False)
    _address = db.Column("address", db.String(512), nullable=False)
    _auth_code = db.Column("auth_code", db.String(255), nullable=False)
    in_distress = db.Column(db.Boolean, default=False)

    links_out = db.relationship('ContactRelation', foreign_keys=[ContactRelation.source_id], backref='source_contact', cascade="all, delete-orphan")
    links_in = db.relationship('ContactRelation', foreign_keys=[ContactRelation.target_id], backref='target_contact', cascade="all, delete-orphan")

    @property
    def name(self): return decrypt_val(self._name)
    @name.setter
    def name(self, val): self._name = encrypt_val(val)

    @property
    def phone(self): return decrypt_val(self._phone)
    @phone.setter
    def phone(self, val): self._phone = encrypt_val(val)

    @property
    def address(self): return decrypt_val(self._address)
    @address.setter
    def address(self, val): self._address = encrypt_val(val)

    @property
    def auth_code(self): return decrypt_val(self._auth_code)
    @auth_code.setter
    def auth_code(self, val):
        if not re.fullmatch(r'\d{12}', val):
            raise ValueError("Personal code must be exactly 12 digits.")
        self._auth_code = encrypt_val(val)

    def get_all_relationships(self):
        related = []
        for rel in self.links_out:
            related.append({'contact': rel.target_contact, 'note': rel.note, 'rel_id': rel.id})
        for rel in self.links_in:
            related.append({'contact': rel.source_contact, 'note': rel.note, 'rel_id': rel.id})
        return related

# --- LOCK & UNLOCK MIDDLEWARE ---

def vault_unlocked_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if ACTIVE_CIPHER is None:
            return redirect(url_for('unlock_vault'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/unlock', methods=['GET', 'POST'])
def unlock_vault():
    global ACTIVE_CIPHER
    if ACTIVE_CIPHER is not None:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        submitted_key = request.form.get('master_key', '').strip()
        try:
            test_cipher = Fernet(submitted_key.encode())
            
            # Verify the key against the first record if any exist
            first_contact = Contact.query.first()
            if first_contact:
                test_cipher.decrypt(first_contact._name.encode())
            
            ACTIVE_CIPHER = test_cipher
            flash("Vault unlocked into server memory.", "success")
            return redirect(url_for('dashboard'))
        except (InvalidToken, ValueError):
            flash("Invalid Master Key. Decryption failed.", "danger")
        except Exception as e:
            flash(f"Error initializing cipher: {str(e)}", "danger")

    return render_template('unlock.html')

@app.route('/lock', methods=['POST'])
def lock_vault():
    global ACTIVE_CIPHER
    ACTIVE_CIPHER = None  # Wipes key from memory
    session.clear()
    flash("Vault locked. Memory cleared.", "success")
    return redirect(url_for('unlock_vault'))

# --- MAIN ROUTES ---

@app.route('/')
@vault_unlocked_required
def dashboard():
    contacts = Contact.query.all()
    return render_template('dashboard.html', contacts=contacts)

@app.route('/verify/<int:contact_id>', methods=['POST'])
@vault_unlocked_required
def verify_code(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    submitted_code = request.form.get('code', '').strip()
    
    if hmac.compare_digest(submitted_code, contact.auth_code):
        flash(f"IDENTITY CONFIRMED: {contact.name} provided valid code.", "success")
    else:
        contact.in_distress = True
        db.session.commit()
        flash(f"DISTRESS SIGNAL: {contact.name} entered INVALID code!", "danger")
        
    return redirect(url_for('dashboard'))

@app.route('/clear-distress/<int:contact_id>', methods=['POST'])
@vault_unlocked_required
def clear_distress(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    contact.in_distress = False
    db.session.commit()
    flash(f"Distress flag cleared for {contact.name}.", "success")
    return redirect(url_for('admin'))

@app.route('/admin', methods=['GET', 'POST'])
@vault_unlocked_required
def admin():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_contact':
            try:
                new_contact = Contact()
                new_contact.name = request.form['name'].strip()
                new_contact.phone = request.form['phone'].strip()
                new_contact.address = request.form['address'].strip()
                new_contact.auth_code = request.form['auth_code'].strip()
                db.session.add(new_contact)
                db.session.commit()
                flash(f"Added: {new_contact.name}", "success")
            except ValueError as e:
                flash(str(e), "danger")
        elif action == 'add_relation':
            rel = ContactRelation(
                source_id=int(request.form['source_id']),
                target_id=int(request.form['target_id']),
                relationship_note=encrypt_val(request.form['note'].strip())
            )
            db.session.add(rel)
            db.session.commit()
            flash("Relationship linked.", "success")
        elif action == 'delete_contact':
            c = Contact.query.get_or_404(int(request.form['contact_id']))
            db.session.delete(c)
            db.session.commit()
            flash("Contact deleted.", "success")

        return redirect(url_for('admin'))

    contacts = Contact.query.all()
    return render_template('admin.html', contacts=contacts)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=4105)