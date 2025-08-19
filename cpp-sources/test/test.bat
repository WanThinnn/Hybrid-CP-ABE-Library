@echo off
setlocal enabledelayedexpansion

echo =========================================
echo HYBRID CP-ABE TEST SUITE - 25 TEST CASES
echo =========================================

:: Tạo thư mục test
if not exist "test_data" mkdir test_data
if not exist "test_keys" mkdir test_keys
if not exist "test_results" mkdir test_results

set TEST_COUNT=0
set PASS_COUNT=0
set FAIL_COUNT=0

:: =============================================================================
:: SETUP - Khởi tạo hệ thống
:: =============================================================================
echo.
echo [SETUP] Initializing CP-ABE system...
.\hybrid-cp-abe.exe setup test_keys
if errorlevel 1 (
    echo [ERROR] Setup failed!
    exit /b 1
) else (
    echo [SUCCESS] Setup completed!
)

:: =============================================================================
:: Tạo các file plaintext mẫu
:: =============================================================================
echo Creating sample plaintext files...

echo This is a confidential medical record for patient ID 12345. > test_data\medical_record.txt
echo Financial report Q4 2024: Revenue $2.5M, Profit $500K > test_data\financial_report.txt
echo Employee John Doe - Manager, IT Department, Salary: $75000 > test_data\hr_record.txt
echo Top Secret: Nuclear launch codes are classified. > test_data\classified_doc.txt
echo Student grades: Alice=A, Bob=B, Charlie=C > test_data\student_grades.txt
echo Research paper: Advanced AI algorithms for medical diagnosis > test_data\research_paper.txt
echo Marketing campaign data for Q1 2025 > test_data\marketing_data.txt
echo IT infrastructure backup procedures and protocols > test_data\it_procedures.txt
echo Board meeting minutes - Executive level discussion > test_data\board_minutes.txt
echo Public announcement: Company holiday schedule > test_data\public_announce.txt

:: =============================================================================
:: TEST CASE 1: Basic Single Attribute
:: =============================================================================
call :run_test "Basic Single Attribute" "doctor" "doctor" "test_data\medical_record.txt" 1

:: =============================================================================
:: TEST CASE 2: Simple AND Operation  
:: =============================================================================
call :run_test "Simple AND" "doctor hospital_a" "doctor and hospital_a" "test_data\medical_record.txt" 2

:: =============================================================================
:: TEST CASE 3: Simple OR Operation
:: =============================================================================
call :run_test "Simple OR" "nurse" "doctor or nurse" "test_data\medical_record.txt" 3

:: =============================================================================
:: TEST CASE 4: Complex AND-OR Mix
:: =============================================================================
call :run_test "AND-OR Mix" "manager finance senior" "(manager and finance) or senior" "test_data\financial_report.txt" 4

:: =============================================================================
:: TEST CASE 5: Age-based Access (Simulated)
:: =============================================================================
call :run_test "Age Range Access" "age_25 age_30 employee" "(age_25 or age_30) and employee" "test_data\hr_record.txt" 5

:: =============================================================================
:: TEST CASE 6: Department-based Access
:: =============================================================================
call :run_test "Department Access" "it_dept senior_level active" "(it_dept and senior_level) and active" "test_data\it_procedures.txt" 6

:: =============================================================================
:: TEST CASE 7: Role-based Hierarchical
:: =============================================================================
call :run_test "Role Hierarchy" "director executive ceo" "director or (executive or ceo)" "test_data\board_minutes.txt" 7

:: =============================================================================
:: TEST CASE 8: Security Clearance Levels
:: =============================================================================
call :run_test "Security Clearance" "top_secret military authorized" "(top_secret and military) and authorized" "test_data\classified_doc.txt" 8

:: =============================================================================
:: TEST CASE 9: Multiple Department Access
:: =============================================================================
call :run_test "Multi Department" "hr_dept finance_dept manager" "(hr_dept or finance_dept) and manager" "test_data\hr_record.txt" 9

:: =============================================================================
:: TEST CASE 10: Student Academic Access
:: =============================================================================
call :run_test "Academic Access" "student cs_dept senior_year" "(student and cs_dept) and senior_year" "test_data\student_grades.txt" 10

:: =============================================================================
:: TEST CASE 11: Research Team Access
:: =============================================================================
call :run_test "Research Team" "researcher phd medical_ai approved" "((researcher and phd) and medical_ai) and approved" "test_data\research_paper.txt" 11

:: =============================================================================
:: TEST CASE 12: Marketing Campaign Access
:: =============================================================================
call :run_test "Marketing Access" "marketing_team campaign_manager q1_2025" "(marketing_team and campaign_manager) and q1_2025" "test_data\marketing_data.txt" 12

:: =============================================================================
:: TEST CASE 13: Salary Range Simulation
:: =============================================================================
call :run_test "Salary Range" "salary_high salary_75k employee_active" "(salary_high or salary_75k) and employee_active" "test_data\hr_record.txt" 13

:: =============================================================================
:: TEST CASE 14: Time-based Access Simulation
:: =============================================================================
call :run_test "Time Based" "working_hours monday_friday authorized" "(working_hours and monday_friday) and authorized" "test_data\it_procedures.txt" 14

:: =============================================================================
:: TEST CASE 15: Emergency Access
:: =============================================================================
call :run_test "Emergency Access" "emergency_staff doctor on_duty" "emergency_staff and (doctor and on_duty)" "test_data\medical_record.txt" 15

:: =============================================================================
:: TEST CASE 16: Public Document Access
:: =============================================================================
call :run_test "Public Access" "employee company_member" "employee or company_member" "test_data\public_announce.txt" 16

:: =============================================================================
:: TEST CASE 17: Complex Nested Policy
:: =============================================================================
call :run_test "Complex Nested" "senior_manager it_director board_member" "(senior_manager and it_director) or board_member" "test_data\it_procedures.txt" 17

:: =============================================================================
:: TEST CASE 18: Multi-level Authorization
:: =============================================================================
call :run_test "Multi-level Auth" "level_1 level_2 level_3 supervisor" "((level_1 or level_2) or level_3) and supervisor" "test_data\classified_doc.txt" 18

:: =============================================================================
:: TEST CASE 19: Project Team Access
:: =============================================================================
call :run_test "Project Team" "project_alpha team_lead developer approved" "(project_alpha and team_lead) and (developer and approved)" "test_data\research_paper.txt" 19

:: =============================================================================
:: TEST CASE 20: Comprehensive Access Control
:: =============================================================================
call :run_test "Comprehensive" "ceo cfo cto board_member executive" "(((ceo or cfo) or cto) and board_member) or executive" "test_data\board_minutes.txt" 20

:: =============================================================================
:: TEST CASE 21: EXTREME COMPLEXITY - Multi-dimensional Access Control
:: =============================================================================
call :run_test "EXTREME COMPLEXITY" "ceo_level_5 board_member finance_director audit_committee security_clearance_alpha project_quantum emergency_override time_critical location_hq department_executive salary_executive experience_senior age_45_55 active_status approved_by_board signed_legal reviewed_compliance" "(((((ceo_level_5 and board_member) and (finance_director or audit_committee)) and ((security_clearance_alpha and project_quantum) and emergency_override)) and (((time_critical and location_hq) and department_executive) and ((salary_executive and experience_senior) and age_45_55))) and (((active_status and approved_by_board) and signed_legal) and reviewed_compliance))" "test_data\classified_doc.txt" 21

:: =============================================================================
:: TEST CASE 22: ULTRA COMPLEX - Nested Conditional Logic
:: =============================================================================
call :run_test "ULTRA COMPLEX NESTED" "admin_root system_architect security_officer database_admin network_admin cloud_architect devops_lead incident_response threat_analyst compliance_officer legal_counsel executive_assistant board_secretary financial_analyst risk_manager audit_specialist" "((((admin_root and system_architect) and (security_officer or database_admin)) or ((network_admin and cloud_architect) and devops_lead)) and (((incident_response and threat_analyst) and compliance_officer) or ((legal_counsel and executive_assistant) and board_secretary))) or (((financial_analyst and risk_manager) and audit_specialist) and (admin_root or system_architect))" "test_data\board_minutes.txt" 22

:: =============================================================================
:: TEST CASE 23: MAXIMUM COMPLEXITY - Real-world Scenario
:: =============================================================================
call :run_test "MAXIMUM COMPLEXITY REAL-WORLD" "physician_license_active malpractice_insurance_current hospital_credentials_verified emergency_medicine_certified trauma_specialist surgical_privileges_level_3 department_head_emergency years_experience_10_plus board_certified_emergency age_range_35_50 shift_night_weekend on_call_status medical_director_approved patient_safety_trained hipaa_compliant background_check_cleared drug_test_current cpr_certified continuing_education_current" "(((((physician_license_active and malpractice_insurance_current) and hospital_credentials_verified) and ((emergency_medicine_certified and trauma_specialist) and surgical_privileges_level_3)) and (((department_head_emergency and years_experience_10_plus) and board_certified_emergency) and ((age_range_35_50 and shift_night_weekend) and on_call_status))) and ((((medical_director_approved and patient_safety_trained) and hipaa_compliant) and ((background_check_cleared and drug_test_current) and cpr_certified)) and continuing_education_current))" "test_data\medical_record.txt" 23

:: =============================================================================
:: TEST CASE 24: EXTREME FINANCIAL ACCESS CONTROL
:: =============================================================================
call :run_test "EXTREME FINANCIAL CONTROL" "cfo_authorized treasury_department_head investment_committee_member regulatory_compliance_certified sox_compliance_trained anti_money_laundering_certified risk_management_specialist financial_crimes_investigator audit_committee_liaison board_finance_committee fiduciary_responsibility_acknowledged conflict_of_interest_cleared insider_trading_trained market_manipulation_awareness quarterly_reporting_certified annual_audit_overseer banking_relationship_manager credit_analysis_expert derivatives_trading_authorized international_finance_certified" "((((((cfo_authorized and treasury_department_head) and investment_committee_member) and ((regulatory_compliance_certified and sox_compliance_trained) and anti_money_laundering_certified)) and (((risk_management_specialist and financial_crimes_investigator) and audit_committee_liaison) and ((board_finance_committee and fiduciary_responsibility_acknowledged) and conflict_of_interest_cleared))) and ((((insider_trading_trained and market_manipulation_awareness) and quarterly_reporting_certified) and ((annual_audit_overseer and banking_relationship_manager) and credit_analysis_expert)) and ((derivatives_trading_authorized and international_finance_certified) and (cfo_authorized or treasury_department_head)))) and (((regulatory_compliance_certified and sox_compliance_trained) and anti_money_laundering_certified) and risk_management_specialist))" "test_data\financial_report.txt" 24

:: =============================================================================
:: TEST CASE 25: INSANE COMPLEXITY - Government Classified System
:: =============================================================================
call :run_test "INSANE GOVERNMENT CLASSIFIED" "top_secret_sci compartmented_information_access special_access_program_read_in nuclear_weapons_personnel_reliability_program crypto_access_authorization foreign_intelligence_surveillance_act_cleared counterintelligence_polygraph_current national_security_background_investigation_tier_5 single_scope_background_investigation_current periodic_reinvestigation_current continuous_evaluation_enrolled foreign_preference_none foreign_influence_mitigated financial_considerations_resolved personal_conduct_adjudicated information_technology_security_certified need_to_know_established official_use_only_handling sensitive_compartmented_information_facility_access program_security_officer_concurrence commanding_officer_endorsement security_control_officer_approval information_system_security_manager_authorization" "(((((((top_secret_sci and compartmented_information_access) and special_access_program_read_in) and ((nuclear_weapons_personnel_reliability_program and crypto_access_authorization) and foreign_intelligence_surveillance_act_cleared)) and (((counterintelligence_polygraph_current and national_security_background_investigation_tier_5) and single_scope_background_investigation_current) and ((periodic_reinvestigation_current and continuous_evaluation_enrolled) and foreign_preference_none))) and ((((foreign_influence_mitigated and financial_considerations_resolved) and personal_conduct_adjudicated) and ((information_technology_security_certified and need_to_know_established) and official_use_only_handling)) and (((sensitive_compartmented_information_facility_access and program_security_officer_concurrence) and commanding_officer_endorsement) and ((security_control_officer_approval and information_system_security_manager_authorization) and (top_secret_sci or compartmented_information_access))))) and (((special_access_program_read_in and nuclear_weapons_personnel_reliability_program) and crypto_access_authorization) and foreign_intelligence_surveillance_act_cleared)) and ((counterintelligence_polygraph_current and national_security_background_investigation_tier_5) and (single_scope_background_investigation_current or periodic_reinvestigation_current)))" "test_data\classified_doc.txt" 25

:: =============================================================================
:: NEGATIVE TEST CASES (Should Fail)
:: =============================================================================
echo.
echo ========== NEGATIVE TEST CASES ==========

:: Test Case N1: Wrong attributes
call :run_negative_test "Wrong Attributes" "janitor intern" "ceo and board_member" "test_data\classified_doc.txt" "N1"

:: Test Case N2: Insufficient privileges
call :run_negative_test "Insufficient Privileges" "student" "professor and department_head" "test_data\research_paper.txt" "N2"

:: Test Case N3: Mismatched policy
call :run_negative_test "Mismatched Policy" "marketing_intern" "(finance_manager and senior) and approved" "test_data\financial_report.txt" "N3"

:: =============================================================================
:: SUMMARY
:: =============================================================================
echo.
echo ==========================================
echo           TEST SUMMARY
echo ==========================================
echo Total Tests: %TEST_COUNT%
echo Passed: %PASS_COUNT%
echo Failed: %FAIL_COUNT%
if %FAIL_COUNT% equ 0 (
    echo STATUS: ALL TESTS PASSED! ✓
) else (
    echo STATUS: %FAIL_COUNT% TEST(S) FAILED! ✗
)
echo ==========================================

goto :end

:: =============================================================================
:: FUNCTIONS
:: =============================================================================

:run_test
set /a TEST_COUNT+=1
echo.
echo [TEST %~5] %~1
echo Attributes: %~2
echo Policy: %~3
echo File: %~4

:: Generate secret key
echo   Generating secret key...
.\hybrid-cp-abe.exe genkey test_keys\public_key.key test_keys\master_key.key "%~2" test_keys\secret_key_%~5.key >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Secret key generation failed
    set /a FAIL_COUNT+=1
    goto :eof
)

:: Encrypt
echo   Encrypting...
.\hybrid-cp-abe.exe encrypt test_keys\public_key.key "%~4" "%~3" test_results\cipher_%~5.enc >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Encryption failed
    set /a FAIL_COUNT+=1
    goto :eof
)

:: Decrypt
echo   Decrypting...
.\hybrid-cp-abe.exe decrypt test_keys\public_key.key test_keys\secret_key_%~5.key test_results\cipher_%~5.enc test_results\recovered_%~5.txt >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Decryption failed
    set /a FAIL_COUNT+=1
    goto :eof
)

:: Verify
echo   Verifying...
fc /B "%~4" test_results\recovered_%~5.txt >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] File verification failed
    set /a FAIL_COUNT+=1
) else (
    echo   [PASS] Test completed successfully ✓
    set /a PASS_COUNT+=1
)
goto :eof

:run_negative_test
set /a TEST_COUNT+=1
echo.
echo [TEST %~5] %~1 (Should Fail)
echo Attributes: %~2
echo Policy: %~3

:: Generate secret key
.\hybrid-cp-abe.exe genkey test_keys\public_key.key test_keys\master_key.key "%~2" test_keys\secret_key_%~5.key >nul 2>&1
if errorlevel 1 (
    echo   [EXPECTED] Secret key generation failed as expected ✓
    set /a PASS_COUNT+=1
    goto :eof
)

:: Encrypt
.\hybrid-cp-abe.exe encrypt test_keys\public_key.key "%~4" "%~3" test_results\cipher_%~5.enc >nul 2>&1
if errorlevel 1 (
    echo   [EXPECTED] Encryption failed as expected ✓
    set /a PASS_COUNT+=1
    goto :eof
)

:: Decrypt (should fail)
.\hybrid-cp-abe.exe decrypt test_keys\public_key.key test_keys\secret_key_%~5.key test_results\cipher_%~5.enc test_results\recovered_%~5.txt >nul 2>&1
if errorlevel 1 (
    echo   [EXPECTED] Decryption failed as expected ✓
    set /a PASS_COUNT+=1
) else (
    echo   [FAIL] Test should have failed but passed ✗
    set /a FAIL_COUNT+=1
)
goto :eof

:end
echo.
echo Test suite completed!
pause