class MedicalHistory:
    def __init__(self, data):
        self.user_id = data.get("username")
        self.first_name = data.get('firstName')
        self.last_name = data.get('lastName')
        self.birth_date = data.get('dob')
        self.gender = data.get('gender')
        self.weight = data.get('weight')
        self.height = data.get('height')
        self.allergies = data.get('allergies')
        self.medications = data.get('medications')
        self.conditions = data.get('conditions')
        self.injuries = data.get('injuries')
        self.has_used_cannabis = data.get('cannabisUse') == 'Yes'
        self.reason_for_visit = data.get('reason')
        self.additional_comments = data.get('comments')
