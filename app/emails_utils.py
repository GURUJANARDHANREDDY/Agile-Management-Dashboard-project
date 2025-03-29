from flask_mail import mail, Message


def send_email_notification(data):
    team_members = {
        "Pranav": "pranav@example.com",
        "Meghana": "vemulameghana9@gmail.com",
        "Suresh": "sureshmenati0@gmail.com",
        "Sania": "saniascoops505@gmail.com",
        "Edward": "ayaan.dhx@gmail.com",
        "Haritha": "haritha.chakka04@gmail.com",
        "Riya": "riyaasthana25@gmail.com",
        "Sai Likitha": "gaddamlikhitha.cse@gmail.com",
        "Dhruv": "dhruvmittal4480@gmail.com",
        "Jasna": "jasnaivi@gmail.com",
        "Janardhan": "reddyjanardhan834@gmail.com",
        "Mahak": "mahakgianchandani124@gmail.com",
        "Karthik": "karthik@example.com",
        "Yashwanthi": "yashwanthimarni77@gmail.com",
        "Vinitha": "vinitha.chirtha@gmail.com",
        "Arun": "ngarun2004@gmail.com",
        "Afreen": "afreen@example.com"
    }

    selected_members = data['devTeam']
    product_owner = data['ProductOwner']
    scrum_masters = [sprint['scrumMaster'] for sprint in data['sprints']]

    subject = f"New Project Created: {data['projectName']}"
    body = f"""
    A new project has been created:
    - Project ID: {data['projectId']}
    - Project Name: {data['projectName']}
    - Description: {data['projectDescription']}
    - Product Owner: {product_owner}
    - Scrum Masters: {', '.join(scrum_masters)}
    - Development Team: {', '.join(selected_members)}
    - Start Date: {data['startDate']}
    - End Date: {data['endDate']}
    - Revised End Date: {data.get('revisedEndDate', 'Not revised')}
    """

    recipients = set()

    if product_owner in team_members:
        recipients.add(team_members[product_owner])

    for master in scrum_masters:
        if master in team_members:
            recipients.add(team_members[master])

    for member in selected_members:
        if member in team_members:
            recipients.add(team_members[member])

    if recipients:
        msg = Message(subject, recipients=list(recipients))
        msg.body = body
        mail.send(msg)
        print(f"Email sent successfully to: {', '.join(recipients)}")
    else:
        print("No valid recipients found to send the email.")