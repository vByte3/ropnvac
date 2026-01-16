"""
Script to populate the database with test data for development/testing.
Run with: python populate_test_data.py
"""
from app import app, db, User, Availability, Announcement, AdminNote
from werkzeug.security import generate_password_hash
from datetime import date, datetime, timedelta
import random

def populate():
    with app.app_context():
        print("� Ensuring database tables exist...")
        db.create_all()
        
        print("�🗑️  Clearing existing data...")
        AdminNote.query.delete()
        Announcement.query.delete()
        Availability.query.delete()
        User.query.delete()
        db.session.commit()
        
        print("👤 Creating test users...")
        users_data = [
            {'name': 'Jean', 'surname': 'Dupont', 'rio': '123456', 'rank': 'PA', 'email': 'jean.dupont@test.fr', 'phone': '0601020304'},
            {'name': 'Marie', 'surname': 'Martin', 'rio': '234567', 'rank': 'GPX', 'email': 'marie.martin@test.fr', 'phone': '0602030405'},
            {'name': 'Pierre', 'surname': 'Bernard', 'rio': '345678', 'rank': 'PA', 'email': 'pierre.bernard@test.fr', 'phone': '0603040506'},
            {'name': 'Sophie', 'surname': 'Dubois', 'rio': '456789', 'rank': 'GPX', 'email': 'sophie.dubois@test.fr', 'phone': '0604050607'},
            {'name': 'Luc', 'surname': 'Thomas', 'rio': '567890', 'rank': 'PA', 'email': 'luc.thomas@test.fr', 'phone': '0605060708'},
            {'name': 'Claire', 'surname': 'Robert', 'rio': '678901', 'rank': 'GPX', 'email': 'claire.robert@test.fr', 'phone': '0606070809'},
        ]
        
        users = []
        for data in users_data:
            user = User(
                name=data['name'],
                surname=data['surname'],
                rio=data['rio'],
                password=generate_password_hash('Test1234'),  # All test users use password: Test1234
                rank=data['rank'],
                date_limit=date(2024, 4, 23),  # Contract anniversary date
                email=data['email'],
                phone=data['phone'],
                status='active'
            )
            db.session.add(user)
            users.append(user)
        
        db.session.commit()
        print(f"✅ Created {len(users)} test users (password: Test1234)")
        
        print("📅 Creating availability entries...")
        today = date.today()
        services = ['Sécurité publique', 'Police secours', 'Investigation', 'Circulation routière', 'Brigade canine']
        statuses = ['pending', 'approved', 'declined']
        
        availability_count = 0
        for user in users:
            # Create 15-25 random availability entries per user over the next 60 days
            num_entries = random.randint(15, 25)
            dates_used = set()
            
            for _ in range(num_entries):
                # Random date in next 60 days
                days_ahead = random.randint(0, 60)
                avail_date = today + timedelta(days=days_ahead)
                
                # Avoid duplicates
                if avail_date.isoformat() in dates_used:
                    continue
                dates_used.add(avail_date.isoformat())
                
                # Weighted status: more pending and approved than declined
                status = random.choices(statuses, weights=[0.4, 0.5, 0.1])[0]
                
                avail = Availability(
                    user_id=user.id,
                    date=avail_date,
                    status=status
                )
                
                if status == 'approved':
                    avail.service = random.choice(services)
                    # Random start time between 6h and 20h
                    start_hour = random.randint(6, 20)
                    end_hour = start_hour + random.randint(4, 10)  # 4-10 hour shifts
                    if end_hour > 23:
                        end_hour = 23
                    avail.start_time = f"{start_hour:02d}:00"
                    avail.end_time = f"{end_hour:02d}:00"
                    avail.reviewed_by = 'admin'
                    avail.reviewed_at = datetime.utcnow() - timedelta(days=random.randint(0, 5))
                    if random.random() < 0.3:  # 30% chance of admin note
                        avail.admin_note = random.choice([
                            'Besoin urgent ce jour-là',
                            'Présence confirmée',
                            'Formation prévue',
                            'Mission spéciale'
                        ])
                
                elif status == 'declined':
                    avail.reviewed_by = 'admin'
                    avail.reviewed_at = datetime.utcnow() - timedelta(days=random.randint(0, 3))
                    avail.admin_note = random.choice([
                        'Effectifs complets',
                        'Date non disponible',
                        'Besoin en autre période',
                        'Congés administratifs'
                    ])
                
                db.session.add(avail)
                availability_count += 1
        
        db.session.commit()
        print(f"✅ Created {availability_count} availability entries")
        
        print("📣 Creating announcements...")
        announcements_data = [
            {
                'title': 'Formation obligatoire',
                'body': 'Rappel : formation aux nouveaux équipements prévue le 25 janvier. Présence obligatoire pour tous les réservistes.',
                'audience': 'all'
            },
            {
                'title': 'Changement d\'horaires',
                'body': 'Les horaires de la brigade de nuit sont modifiés à partir du 1er février : 20h-6h.',
                'audience': 'all'
            },
            {
                'title': 'Alerte effectifs',
                'body': 'Besoin urgent de réservistes pour le week-end du 20-21 janvier. Merci de vous positionner rapidement.',
                'audience': 'all'
            },
        ]
        
        for data in announcements_data:
            ann = Announcement(
                title=data['title'],
                body=data['body'],
                audience=data['audience'],
                created_by='admin',
                created_at=datetime.utcnow() - timedelta(days=random.randint(0, 10))
            )
            db.session.add(ann)
        
        db.session.commit()
        print(f"✅ Created {len(announcements_data)} announcements")
        
        print("📝 Creating admin notes...")
        notes_data = [
            'Très fiable, ponctuel',
            'Excellente attitude professionnelle',
            'À prioriser pour les missions sensibles',
            'Préfère les horaires de jour',
            'Disponible en urgence'
        ]
        
        note_count = 0
        for user in random.sample(users, 3):  # Add notes to 3 random users
            for _ in range(random.randint(1, 3)):
                note = AdminNote(
                    user_id=user.id,
                    note=random.choice(notes_data),
                    created_by='admin',
                    created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30))
                )
                db.session.add(note)
                note_count += 1
        
        db.session.commit()
        print(f"✅ Created {note_count} admin notes")
        
        print("\n🎉 Test data population complete!")
        print("\n📋 Summary:")
        print(f"   • Users: {len(users)}")
        print(f"   • Availabilities: {availability_count}")
        print(f"   • Announcements: {len(announcements_data)}")
        print(f"   • Admin notes: {note_count}")
        print("\n🔐 Login credentials:")
        print("   Admin: ADMIN_USER / ADMIN_PASS (from .env)")
        for u in users[:3]:
            print(f"   User: {u.rio} / Test1234")

if __name__ == '__main__':
    populate()
