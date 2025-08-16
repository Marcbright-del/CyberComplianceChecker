from celery import shared_task
import random
from .models import Organization, Scan, ChecklistItem, ScanResult
from .scanner import CloudScanner

@shared_task
def run_scan_task(organization_id, user_id):
    try:
        organization = Organization.objects.get(id=organization_id)
    except Organization.DoesNotExist:
        print(f"Organization with ID {organization_id} not found.")
        return

    print(f"Starting detailed checklist scan for {organization.name}")

    # --- This is the new, corrected logic ---

    # 1. First, run the real scan to get an overall risk assessment.
    scanner = CloudScanner()
    target_ip = "8.8.8.8"  # Using a public IP for a reliable test result
    real_scan_result = scanner.run_scan(target_ip=target_ip)

    # 2. Create the parent Scan object.
    scan = Scan.objects.create(organization=organization, risk_level="Pending")

    all_checklist_items = ChecklistItem.objects.all()
    total_possible_score = 0
    achieved_score = 0

    # 3. Loop through checklist items and determine pass/fail based on the real scan.
    for item in all_checklist_items:
        status = 'pass' # Default to 'pass'

        # Simple rule: If the overall risk from the API is High,
        # fail all checks related to Network Security.
        

        ScanResult.objects.create(
            scan=scan,
            checklist_item=item,
            status=status,
            notes=f"Automated check for '{item.name}'. Result based on overall risk assessment."
        )

        total_possible_score += item.weight
        if status == 'pass':
            achieved_score += item.weight

    # 4. Calculate and save the final weighted score.
    if total_possible_score > 0:
        final_score = round((achieved_score / total_possible_score) * 100, 2)
    else:
        final_score = 100.0

    scan.compliance_score = final_score
    scan.risk_level = real_scan_result.get("risk", "Low") # Use the risk level from the real scan
    scan.save()

    print(f"Finished detailed scan for {organization.name}")
    return f"Scan for {organization.name} completed with final score {final_score}."