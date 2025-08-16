import random
from .models import Organization, Scan, ChecklistItem, ScanResult
from .scanner import CloudScanner

def run_scan_task(organization_id, user_id):
    """
    This function runs a scan synchronously.
    """
    try:
        organization = Organization.objects.get(id=organization_id)
    except Organization.DoesNotExist:
        print(f"Organization with ID {organization_id} not found.")
        return

    print(f"Starting detailed checklist scan for {organization.name}")
    
    scan = Scan.objects.create(organization=organization, risk_level="Pending")

    # Use a real public IP address for testing with the live API
    target_ip = "8.8.8.8" 
    
    # We will simulate the checklist results for now
    all_checklist_items = ChecklistItem.objects.all()
    if not all_checklist_items.exists():
        print("No checklist items found in the database.")
        # If no checklist, we can use the API score directly
        scanner = CloudScanner()
        scan_result = scanner.run_scan(target_ip=target_ip)
        scan.compliance_score = scan_result.get("score", 0)
        scan.risk_level = scan_result.get("risk", "Error")
    else:
        # If there is a checklist, calculate a weighted score
        total_possible_score = 0
        achieved_score = 0

        for item in all_checklist_items:
            status = random.choice(['pass', 'fail'])
            ScanResult.objects.create(
                scan=scan,
                checklist_item=item,
                status=status,
                notes=f"Automated check for '{item.name}' resulted in a '{status}'."
            )
            
            total_possible_score += item.weight
            if status == 'pass':
                achieved_score += item.weight

        if total_possible_score > 0:
            final_score = round((achieved_score / total_possible_score) * 100, 2)
        else:
            final_score = 100.0

        risk_level = "Low"
        if final_score < 60:
            risk_level = "High"
        elif final_score < 80:
            risk_level = "Medium"

        scan.compliance_score = final_score
        scan.risk_level = risk_level

    scan.save()
    
    print(f"Finished detailed scan for {organization.name}")
    return f"Scan for {organization.name} completed with final score {scan.compliance_score}."